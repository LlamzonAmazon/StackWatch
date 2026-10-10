"""NVD CPE matching: offline, with a recorded NVD API 2.0 response and the HTTP layer mocked."""

import json
from pathlib import Path

import pytest

from app import config
from app.intel import nvd, threat
from app.intel.cpe import cpe_for, virtual_match_string
from app.intel.threat import cve_ids
from app.recon.kb import Tech
from app.schema import Target

FIX = Path(__file__).parent / "fixtures" / "intel"
NGINX = (FIX / "nvd_nginx_1_18_0.json").read_bytes()


def emit(*_):
    pass


class Nvd:
    """Stands in for threat._http_get; records every call including its headers."""

    def __init__(self, body: bytes = NGINX):
        self.body = body
        self.calls: list[tuple[str, dict, dict]] = []
        self.fail = False

    def __call__(self, url, params, max_bytes, headers=None):
        self.calls.append((url, dict(params or {}), dict(headers or {})))
        if self.fail:
            raise ConnectionError("nvd down")
        return self.body


@pytest.fixture
def api(tmp_path, monkeypatch):
    a = Nvd()
    monkeypatch.setattr(nvd, "CACHE_DIR", tmp_path / "nvd")
    monkeypatch.setattr(threat, "_http_get", a)
    monkeypatch.setattr(config, "CACHE_ONLY", False)
    monkeypatch.setattr(config, "NVD_API_KEY", None)
    monkeypatch.setattr(nvd, "_last_request", 0.0)
    monkeypatch.setattr(nvd, "_sleep", lambda s: None)
    return a


# --------------------------------------------------------------------------- #
# curated CPE table
# --------------------------------------------------------------------------- #

def test_cpe_table_names_known_products_only():
    assert cpe_for("nginx") == ("f5", "nginx")
    assert cpe_for("Apache") == ("apache", "http_server")
    assert cpe_for("PHP") == ("php", "php")
    assert cpe_for("Some Unknown CMS") is None
    assert cpe_for("jQuery") is None  # JS libraries go through OSV by npm name
    assert cpe_for(None) is None
    assert virtual_match_string("f5", "nginx", "1.18.0") == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------- #
# loose version compare
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("a,b,want", [
    ("1.18.0", "1.20.1", -1), ("1.20.1", "1.18.0", 1), ("1.2", "1.2.0", 0), ("v2.4.41", "2.4.41", 0),
    ("1.9", "1.10", -1), ("2.4.41-rc1", "2.4.41", -1), ("2.4.41", "2.4.41-beta.2", 1),
    ("1.0.2k", "1.0.2", 1), ("1.0.2a", "1.0.2k", -1), ("5.3", "5.3.0.0", 0),
    ("10.0", "9.9.9", 1), ("1.2.3.4", "1.2.3", 1),
])
def test_compare_handles_non_semver(a, b, want):
    assert nvd.compare(a, b) == want


@pytest.mark.parametrize("a,b", [
    ("r22", "1.0"), ("1.0", "r22"), ("", "1.0"), ("abc", "def"), ("2023-10-08", "x"),
    ("10.2\\(7\\)", "release"),
])
def test_compare_never_crashes_and_returns_none_when_unorderable(a, b):
    assert nvd.compare(a, b) is None


# --------------------------------------------------------------------------- #
# range evaluation
# --------------------------------------------------------------------------- #

def cfg(*matches, op=None, extra_nodes=()):
    nodes = [{"operator": "OR", "matches": list(matches)}, *extra_nodes]
    return [{"operator": op, "nodes": nodes}]


def m(version="*", vendor="f5", product="nginx", **bounds):
    return {"criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*", **bounds}


@pytest.mark.parametrize("version,bounds,hit", [
    ("1.18.0", {"versionEndExcluding": "1.20.1"}, True),
    ("1.20.1", {"versionEndExcluding": "1.20.1"}, False),
    ("1.20.1", {"versionEndIncluding": "1.20.1"}, True),
    ("1.0.0", {"versionStartIncluding": "1.1.3", "versionEndIncluding": "1.22.0"}, False),
    ("1.1.3", {"versionStartIncluding": "1.1.3"}, True),
    ("1.1.3", {"versionStartExcluding": "1.1.3"}, False),
    ("1.18.0", {}, True),  # no bounds at all: every version
    ("1.18.0", {"versionEndExcluding": "r33"}, False),  # unorderable bound: no claim
])
def test_ranges(version, bounds, hit):
    verdict, _, _ = nvd.affects(version, cfg(m(**bounds)), "f5", "nginx")
    assert (verdict == "confirmed") is hit


def test_specific_version_and_not_applicable():
    assert nvd.affects("1.23.0", cfg(m("1.23.0")), "f5", "nginx")[0] == "confirmed"
    assert nvd.affects("1.23.1", cfg(m("1.23.0")), "f5", "nginx")[0] is None
    assert nvd.affects("1.23.0", cfg(m("-")), "f5", "nginx")[0] is None


def test_other_products_never_match():
    assert nvd.affects("1.18.0", cfg(m(vendor="f5", product="nginx_plus")), "f5", "nginx")[0] is None
    assert nvd.affects("1.18.0", cfg(m(vendor="openresty", product="nginx")), "f5", "nginx")[0] is None


def test_and_configuration_is_only_possible():
    assert nvd.affects("1.18.0", cfg(m(), op="AND"), "f5", "nginx")[0] == "possible"
    both = cfg(m(), op="AND") + cfg(m())
    assert nvd.affects("1.18.0", both, "f5", "nginx")[0] == "confirmed"  # any plain config wins


def test_range_text_and_fixed_version():
    verdict, rng, fixed = nvd.affects(
        "1.18.0", cfg(m(versionStartIncluding="0.6.18", versionEndExcluding="1.20.1")),
        "f5", "nginx")
    assert (verdict, rng, fixed) == ("confirmed", ">=0.6.18 <1.20.1", "1.20.1")


def test_escaped_colon_in_cpe_does_not_shift_fields():
    odd = cfg({"criteria": "cpe:2.3:a:f5:nginx:1.18.0\\:x:*:*:*:*:*:*:*"})
    assert nvd.cpe_fields(odd[0]["nodes"][0]["matches"][0]["criteria"])[5] == "1.18.0:x"


# --------------------------------------------------------------------------- #
# recorded NVD response
# --------------------------------------------------------------------------- #

def test_recorded_nginx_response(api):
    vulns = nvd.query_product("f5", "nginx", "1.18.0", emit)
    got = {x.cve_id: x for x in nvd.match_vulns(vulns, "f5", "nginx", "1.18.0")}
    assert {"CVE-2021-23017", "CVE-2021-3618", "CVE-2022-41741", "CVE-2022-41742",
            "CVE-2025-23419"} <= set(got)
    c = got["CVE-2021-23017"]
    assert c.match == "confirmed" and c.fixed_version == "1.20.1"
    assert c.affected_range == ">=0.6.18 <1.20.1"
    assert c.severity in ("critical", "high", "medium", "low") and c.cvss_score
    assert c.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
    # sorted by CVSS, highest first
    scores = [x.cvss_score or 0 for x in nvd.match_vulns(vulns, "f5", "nginx", "1.18.0")]
    assert scores == sorted(scores, reverse=True)


def test_same_response_for_a_fixed_version_matches_less(api):
    vulns = nvd.query_product("f5", "nginx", "1.18.0", emit)
    old = {x.cve_id for x in nvd.match_vulns(vulns, "f5", "nginx", "1.18.0")}
    new = {x.cve_id for x in nvd.match_vulns(vulns, "f5", "nginx", "1.27.0")}
    assert "CVE-2021-23017" in old and "CVE-2021-23017" not in new
    assert "CVE-2025-23419" in new  # 1.27.0 is inside 1.27.0 to 1.27.4


def test_unrelated_product_in_the_response_is_ignored(api):
    vulns = nvd.query_product("f5", "nginx", "1.18.0", emit)
    assert nvd.match_vulns(vulns, "apache", "http_server", "2.4.41") == []


# --------------------------------------------------------------------------- #
# client behavior: key, cache, rate limit, failure
# --------------------------------------------------------------------------- #

def test_no_key_sends_no_api_key_header(api):
    nvd.query_product("f5", "nginx", "1.18.0", emit)
    url, params, headers = api.calls[0]
    assert url == nvd.NVD_URL and "apiKey" not in headers
    assert params["virtualMatchString"] == virtual_match_string("f5", "nginx", "1.18.0")


def test_key_is_sent_as_header_only_and_never_emitted(api, monkeypatch):
    shape = "k" * 8 + "-0000-0000"  # a made-up value; only its handling is under test
    monkeypatch.setattr(config, "NVD_API_KEY", shape)
    events = []
    nvd.query_product("f5", "nginx", "1.18.0", lambda *a: events.append(a))
    _, params, headers = api.calls[0]
    assert headers == {"apiKey": shape}
    assert shape not in json.dumps(params) and shape not in json.dumps(events)
    api.fail = True
    nvd.query_product("f5", "nginx", "9.9.9", lambda *a: events.append(a))
    assert shape not in json.dumps(events)  # failure messages never carry it


def test_second_query_is_served_from_cache(api):
    nvd.query_product("f5", "nginx", "1.18.0", emit)
    api.fail = True
    again = nvd.query_product("f5", "nginx", "1.18.0", emit)
    assert again and len(api.calls) == 1


def test_cache_only_with_a_cold_cache_makes_no_request(api, monkeypatch):
    monkeypatch.setattr(config, "CACHE_ONLY", True)
    assert nvd.query_product("f5", "nginx", "1.18.0", emit) is None
    assert api.calls == []


def test_outage_returns_none_with_a_warning_and_uses_a_stale_cache(api, monkeypatch):
    api.fail = True
    events = []
    assert nvd.query_product("f5", "nginx", "1.18.0", lambda *a: events.append(a)) is None
    assert any(e[1] == "warn" for e in events)
    api.fail = False
    nvd.query_product("f5", "nginx", "1.18.0", emit)
    monkeypatch.setattr(nvd, "CACHE_TTL", -1)
    api.fail = True
    assert nvd.query_product("f5", "nginx", "1.18.0", emit)  # stale beats nothing


def test_rate_limit_spaces_requests_and_a_key_loosens_it(api, monkeypatch):
    clock = {"t": 100.0}
    waits = []
    monkeypatch.setattr(nvd, "_clock", lambda: clock["t"])
    monkeypatch.setattr(nvd, "_sleep", lambda s: (waits.append(round(s, 2)),
                                                  clock.update(t=clock["t"] + s)))
    nvd.query_product("f5", "nginx", "1.18.0", emit)
    nvd.query_product("f5", "nginx", "1.19.0", emit)
    assert waits == [6.5]
    monkeypatch.setattr(config, "NVD_API_KEY", "x" * 8)
    nvd.query_product("f5", "nginx", "1.20.0", emit)
    assert waits[-1] == 0.7


def test_pagination_follows_total_results(api, monkeypatch):
    pages = []

    def paged(url, params, max_bytes, headers=None):
        pages.append(params["startIndex"])
        body = json.loads(NGINX)
        body.update(resultsPerPage=len(body["vulnerabilities"]), totalResults=12,
                    startIndex=params["startIndex"])
        return json.dumps(body).encode()

    monkeypatch.setattr(threat, "_http_get", paged)
    vulns = nvd.query_product("f5", "nginx", "1.18.0", emit)
    assert pages == [0, 6] and len(vulns) == 12


# --------------------------------------------------------------------------- #
# products and rows
# --------------------------------------------------------------------------- #

def tech(name, version, **kw):
    return Tech(name=name, category="web-server", version=version, confidence="high",
                evidence=f"Server: {name}/{version}", source="https://acme.example/", **kw)


def test_match_products_skips_unknown_unversioned_and_npm_techs(api):
    techs = [tech("nginx", "1.18.0"), tech("Mystery", "2.0"), tech("Apache", None),
             tech("jQuery", "3.5.1"), tech("nginx", "1.18.0")]
    matches, status = nvd.match_products(techs, emit)
    assert status == "ok" and len(api.calls) == 1  # duplicates collapse, unknowns never queried
    assert {x.name for x in matches} == {"nginx"}
    assert all(x.evidence == "Server: nginx/1.18.0" and x.confidence == "high" for x in matches)


def test_match_products_with_nothing_to_check_is_skipped(api):
    assert nvd.match_products([tech("Mystery", "2.0")], emit) == ([], "skipped")
    assert api.calls == []


def test_match_products_reports_failed_and_partial(api):
    api.fail = True
    assert nvd.match_products([tech("nginx", "1.18.0")], emit)[1] == "failed"


def test_nvd_rows_feed_the_same_tables_as_osv(api):
    from app.orchestrator import _nvd_rows

    matches, _ = nvd.match_products([tech("nginx", "1.18.0")], emit)
    target = Target(target_id="t_acme", kind="public", name="acme", domain="acme.example")
    items, advs, cands, vers = _nvd_rows(matches, "r1", target)
    assert len(items) == 1 and items[0].ecosystem == "cpe" and items[0].package == "f5:nginx"
    assert items[0].version == "1.18.0" and items[0].evidence == "Server: nginx/1.18.0"
    assert len(advs) == len(cands) == len(vers) == len(matches)
    adv = advs[0]
    assert adv.source == "nvd" and adv.ecosystem == "cpe" and adv.advisory_id.startswith("CVE-")
    assert cve_ids(adv.advisory_id, adv.aliases) == [adv.advisory_id]  # KEV/EPSS join key
    cand = cands[0]
    assert cand.stack_item_id == items[0].id and cand.advisory_id == adv.advisory_id
    assert cand.match_type in ("confirmed", "possible") and cand.risk_score >= 1
    assert vers[0].status == "present" and vers[0].candidate_id == cand.id
    assert vers[0].checks_performed == ["nvd:cpe"]


def test_nvd_findings_get_kev_and_epss_like_osv_findings(api):
    from app.correlate.score import intel_risk_boost

    matches, _ = nvd.match_products([tech("nginx", "1.18.0")], emit)
    table = threat.IntelTable(
        kev={"CVE-2021-23017": {"added": "2024-01-01", "due": "2024-01-22", "ransomware": False}},
        epss={"CVE-2021-23017": {"epss": 0.7, "percentile": 0.97}})
    by_cve = {x.cve_id: threat.intel_for(cve_ids(x.cve_id, []), table) for x in matches}
    assert by_cve["CVE-2021-23017"].kev and intel_risk_boost(by_cve["CVE-2021-23017"]) > 0
    assert by_cve["CVE-2021-3618"].kev is False and by_cve["CVE-2021-3618"].epss is None


def test_record_and_mirror_into_the_public_kb(api, monkeypatch):
    from app import orchestrator
    from app.recon import runner
    from app.recon.kb import KnowledgeBase

    kb = KnowledgeBase(domain="acme.example", run_id="r_nvd", target_id="t_acme")
    kb.stack.append(tech("nginx", "1.18.0"))
    monkeypatch.setattr(runner.store, "insert_knowledge", lambda *a, **k: None)
    runner.save(kb)
    matches = orchestrator._record_nvd("r_nvd", emit)
    assert matches and kb.coverage["nvd"] == "ok"
    table = threat.IntelTable(
        kev={"CVE-2021-23017": {"added": "2024-01-01", "due": "2024-01-22", "ransomware": True}},
        epss={})
    orchestrator._mirror_nvd("r_nvd", matches, table, emit)
    hits = {h.id: h for h in kb.intel if h.source == "nvd"}
    assert hits["CVE-2021-23017"].kev and hits["CVE-2021-23017"].kev_ransomware
    assert hits["CVE-2021-23017"].tech == "nginx"
    assert not hits["CVE-2021-3618"].kev
    assert orchestrator._record_nvd("r_missing", emit) == []  # repo targets have no live KB
