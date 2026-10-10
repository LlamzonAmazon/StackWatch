"""API key auth and per-IP rate limiting (SECURITY_AUDIT H-3, M-5)."""

from unittest.mock import MagicMock

import httpx
import pytest

pytest.importorskip("clickhouse_connect", reason="project deps not installed; see SECURITY_AUDIT.md for setup")

from app import auth, config, main

API_KEY = "a" * 40
OTHER_KEY = "b" * 40

# Every documented /api operation; a route added later is covered automatically.
PROTECTED = sorted(
    (method.upper(), path)
    for path, ops in main.app.openapi()["paths"].items()
    if path.startswith("/api/") and path != "/api/health"
    for method in ops
)


def _concrete(path: str) -> str:
    return path.replace("{run_id}", "r_20261009_120000_abcd").replace("{target_id}", "t_any")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def api_auth(monkeypatch):
    monkeypatch.setattr(config, "API_KEYS", [API_KEY])
    monkeypatch.setattr(config, "AUTH_DISABLED", False)
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 3)
    monkeypatch.setattr(main, "DEMO_MODE", False)
    auth.limiter.reset()


@pytest.fixture(autouse=True)
def no_clickhouse(monkeypatch):
    """Any handler that runs touches only these mocks; auth failures never reach them."""
    fake = MagicMock()
    fake.query.return_value.result_rows = []
    for name, value in {
        "get_client": lambda: fake,
        "get_corpus_stats": MagicMock(return_value={}),
        "get_record_counts": MagicMock(return_value={}),
        "get_last_query_latency": MagicMock(return_value=None),
    }.items():
        monkeypatch.setattr(main.store, name, value)
    return fake


def _client(ip: str = "203.0.113.7", key: str | None = API_KEY) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=main.app, client=(ip, 50000))
    headers = {"X-API-Key": key} if key is not None else {}
    return httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers)


pytestmark = pytest.mark.anyio


def test_route_inventory():
    assert len(PROTECTED) == 14


@pytest.mark.parametrize("method,path", PROTECTED)
@pytest.mark.parametrize("key", [None, "", "wrong", OTHER_KEY, API_KEY + "x", API_KEY[:-1]])
async def test_protected_routes_reject_missing_or_bad_key(method, path, key):
    async with _client(key=key) as c:
        r = await c.request(method, _concrete(path), json={})
    assert r.status_code == 401, (method, path, r.text)
    assert r.headers["www-authenticate"] == "X-API-Key"


async def test_valid_key_is_accepted():
    async with _client() as c:
        assert (await c.get("/api/stats")).status_code == 200


async def test_any_configured_key_is_accepted(monkeypatch):
    monkeypatch.setattr(config, "API_KEYS", [API_KEY, OTHER_KEY])
    async with _client(key=OTHER_KEY) as c:
        assert (await c.get("/api/stats")).status_code == 200


async def test_health_is_public():
    async with _client(key=None) as c:
        assert (await c.get("/api/health")).status_code == 200


@pytest.mark.parametrize("keys", [[], ["short-key"]])
async def test_fails_closed_without_a_usable_key(monkeypatch, keys):
    monkeypatch.setattr(config, "API_KEYS", keys)
    async with _client(key=keys[0] if keys else "anything") as c:
        r = await c.get("/api/stats")
    assert r.status_code == 503


async def test_explicit_opt_out_disables_auth(monkeypatch):
    monkeypatch.setattr(config, "API_KEYS", [])
    monkeypatch.setattr(config, "AUTH_DISABLED", True)
    async with _client(key=None) as c:
        assert (await c.get("/api/stats")).status_code == 200


# Rate limiting

async def test_rate_limit_per_ip_on_expensive_routes():
    # Replay answers 404 outside demo mode, but the limit is applied before the handler runs.
    body = {"advisory_id": "GHSA-1"}
    async with _client() as c:
        codes = [(await c.post("/api/advisories/replay", json=body)).status_code for _ in range(4)]
        assert codes == [404, 404, 404, 429]
        blocked = await c.post("/api/advisories/replay", json=body)
        assert 1 <= int(blocked.headers["retry-after"]) <= 60
    async with _client(ip="198.51.100.9") as other:
        assert (await other.post("/api/advisories/replay", json=body)).status_code == 404


async def test_rate_limit_ignores_forwarded_for():
    body = {"advisory_id": "GHSA-1"}
    async with _client() as c:
        for i in range(4):
            r = await c.post("/api/advisories/replay", json=body,
                             headers={"X-Forwarded-For": f"10.0.0.{i}"})
    assert r.status_code == 429


async def test_rate_limit_skips_cheap_reads():
    async with _client() as c:
        assert all([(await c.get("/api/stats")).status_code == 200 for _ in range(10)])


async def test_unauthenticated_requests_do_not_consume_the_budget():
    async with _client(key="wrong") as bad:
        for _ in range(5):
            await bad.post("/api/advisories/replay", json={"advisory_id": "GHSA-1"})
    async with _client() as c:
        r = await c.post("/api/advisories/replay", json={"advisory_id": "GHSA-1"})
    assert r.status_code == 404


def test_sliding_window_recovers():
    now = [0.0]
    limiter = auth.RateLimiter(window=60, clock=lambda: now[0])
    assert [limiter.hit("ip", 2) for _ in range(2)] == [None, None]
    assert limiter.hit("ip", 2) == 60
    now[0] = 30
    assert limiter.hit("ip", 2) == 30
    now[0] = 60.5
    assert limiter.hit("ip", 2) is None


def test_stale_clients_are_swept(monkeypatch):
    now = [0.0]
    limiter = auth.RateLimiter(window=60, clock=lambda: now[0])
    monkeypatch.setattr(auth.RateLimiter, "SWEEP_AT", 3)
    for ip in ("a", "b", "c"):
        limiter.hit(ip, 5)
    now[0] = 61
    limiter.hit("d", 5)
    assert set(limiter._hits) == {"d"}


@pytest.mark.parametrize("host,expected", [
    ("203.0.113.7", "203.0.113.7"),
    ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:bbbb::9", "2001:db8:1:2::/64"),
    (None, "unknown"),
    ("testclient", "testclient"),
])
def test_client_key(host, expected):
    assert auth.client_key(host) == expected
