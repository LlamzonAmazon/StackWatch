"""NVD CVE matching by CPE for fingerprinted server software.

For each fingerprinted product with a version and a curated CPE (see app.intel.cpe), ask NVD API
2.0 for CVEs whose configurations match that version, then re-check every version range here so
the verdict never rests on the API's own matching alone. Responses are cached on disk, the
request rate stays under NVD's public limits, and any failure leaves the product unmatched with a
warning; it never fails a run. NVD_API_KEY, when set, is sent as the apiKey header and nowhere
else.
"""

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from app import config
from app.intel import threat
from app.intel.cpe import cpe_for, virtual_match_string
from app.schema import Emit

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = Path("data/cache/intel/nvd")
CACHE_TTL = 24 * 3600
MAX_BYTES = 16 * 1024 * 1024
PAGE_SIZE = 2000
MAX_PAGES = 3
MAX_PRODUCTS = 10  # per run; keeps a keyless run inside a minute or so
MAX_PER_PRODUCT = 50  # highest CVSS first
# NVD allows 5 requests per rolling 30s without a key and 50 with one.
MIN_INTERVAL = 6.5
MIN_INTERVAL_KEYED = 0.7

_last_request = 0.0
_sleep = time.sleep
_clock = time.monotonic


@dataclass
class NvdMatch:
    cve_id: str
    summary: str
    severity: str  # critical, high, medium, low, unknown
    cvss_score: float | None
    cvss_vector: str | None
    cwes: list[str]
    published: str | None
    modified: str | None
    match: str  # confirmed, possible
    affected_range: str
    fixed_version: str | None
    vendor: str
    product: str
    version: str
    name: str = ""  # the fingerprinted tech's display name
    confidence: str = "medium"  # of the version fingerprint
    evidence: str = ""  # what showed the version, e.g. "Server: nginx/1.18.0"
    source_url: str = ""

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


def match_products(techs, emit: Emit) -> tuple[list[NvdMatch], str]:
    """NVD matches for fingerprinted techs, and a coverage status (ok, partial, failed, skipped)."""
    todo, seen = [], set()
    for t in techs:
        cpe = cpe_for(t.name)
        key = (cpe, t.version)
        if cpe and t.version and key not in seen:
            seen.add(key)
            todo.append((t, cpe))
    if not todo:
        return [], "skipped"
    if len(todo) > MAX_PRODUCTS:
        emit("intel", "info", f"NVD: checking the first {MAX_PRODUCTS} of {len(todo)} "
             "fingerprinted products", None)
        todo = todo[:MAX_PRODUCTS]
    out: list[NvdMatch] = []
    failed = 0
    for t, (vendor, product) in todo:
        vulns = query_product(vendor, product, t.version, emit)
        if vulns is None:
            failed += 1
            continue
        found = match_vulns(vulns, vendor, product, t.version)
        emit("intel", "info", f"NVD: {t.name} {t.version} matches {len(found)} CVEs"
             + (f" (keeping the top {MAX_PER_PRODUCT} by CVSS)" if len(found) > MAX_PER_PRODUCT
                else ""), None)
        for m in found[:MAX_PER_PRODUCT]:
            m.name, m.confidence = t.name, t.confidence
            m.evidence, m.source_url = t.evidence, t.source
            out.append(m)
    if failed == len(todo) and config.CACHE_ONLY:
        return out, "skipped"
    status = "ok" if not failed else ("failed" if failed == len(todo) else "partial")
    return out, status


# --------------------------------------------------------------------------- #
# NVD API
# --------------------------------------------------------------------------- #

def query_product(vendor: str, product: str, version: str, emit: Emit) -> list[dict] | None:
    """Reduced CVE records for a product version, from cache or NVD. None when unavailable."""
    path = CACHE_DIR / (re.sub(r"[^a-z0-9._-]", "_", f"{vendor}__{product}__{version}".lower())
                        + ".json")
    cached = _read(path)
    if cached is not None and time.time() - path.stat().st_mtime < CACHE_TTL:
        return cached
    if config.CACHE_ONLY:
        return cached  # stale or None; no network in cache-only mode
    try:
        vulns = _fetch_all(virtual_match_string(vendor, product, version))
    except Exception as e:  # noqa: BLE001 - NVD trouble must not fail a run
        emit("intel", "warn", f"NVD query for {vendor}:{product} {version} failed: "
             f"{type(e).__name__}", None)
        return cached
    _write(path, vulns)
    return vulns


def _fetch_all(match_string: str) -> list[dict]:
    out: list[dict] = []
    start = 0
    for _ in range(MAX_PAGES):
        _throttle()
        body = json.loads(threat._http_get(
            NVD_URL, {"virtualMatchString": match_string, "resultsPerPage": PAGE_SIZE,
                      "startIndex": start}, MAX_BYTES, _headers()))
        out += [_reduce(v["cve"]) for v in body.get("vulnerabilities", []) if v.get("cve")]
        start += int(body.get("resultsPerPage") or 0)
        if start >= int(body.get("totalResults") or 0) or not body.get("resultsPerPage"):
            break
    return out


def _headers() -> dict:
    key = config.NVD_API_KEY
    return {"apiKey": key} if key else {}


def _throttle() -> None:
    """Space requests under NVD's rolling limit (a keyless caller gets a fraction of it)."""
    global _last_request
    gap = MIN_INTERVAL_KEYED if config.NVD_API_KEY else MIN_INTERVAL
    wait = _last_request + gap - _clock()
    if _last_request and wait > 0:
        _sleep(wait)
    _last_request = _clock()


def _reduce(cve: dict) -> dict:
    """Keep only what matching and display need, so the cache stays small."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score = vector = sev = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
            data = primary.get("cvssData") or {}
            score, vector = data.get("baseScore"), data.get("vectorString")
            sev = (data.get("baseSeverity") or primary.get("baseSeverity") or "").lower() or None
            break
    cwes = [d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description") or []
            if str(d.get("value", "")).startswith("CWE-")]
    configs = []
    for c in cve.get("configurations") or []:
        nodes = [{"operator": n.get("operator"), "matches": [
            {k: m[k] for k in ("criteria", "versionStartIncluding", "versionStartExcluding",
                               "versionEndIncluding", "versionEndExcluding") if k in m}
            for m in n.get("cpeMatch") or [] if m.get("vulnerable")]}
            for n in c.get("nodes") or []]
        configs.append({"operator": c.get("operator"), "nodes": nodes})
    return {"id": cve.get("id"), "summary": desc, "score": score, "vector": vector,
            "severity": sev, "cwes": sorted(set(cwes)), "published": cve.get("published"),
            "modified": cve.get("lastModified"), "configurations": configs}


# --------------------------------------------------------------------------- #
# matching
# --------------------------------------------------------------------------- #

def match_vulns(vulns: list[dict], vendor: str, product: str, version: str) -> list[NvdMatch]:
    out = []
    for v in vulns:
        verdict, rng, fixed = affects(version, v.get("configurations") or [], vendor, product)
        if not verdict or not v.get("id"):
            continue
        sev = v.get("severity") if v.get("severity") in ("critical", "high", "medium", "low") \
            else "unknown"
        out.append(NvdMatch(
            cve_id=v["id"], summary=v.get("summary") or v["id"], severity=sev,
            cvss_score=v.get("score"), cvss_vector=v.get("vector"), cwes=v.get("cwes") or [],
            published=v.get("published"), modified=v.get("modified"), match=verdict,
            affected_range=rng, fixed_version=fixed, vendor=vendor, product=product,
            version=version))
    out.sort(key=lambda m: (-(m.cvss_score or 0), m.cve_id))
    return out


def affects(version: str, configurations: list[dict], vendor: str,
            product: str) -> tuple[str | None, str, str | None]:
    """(verdict, range text, fixed version) for a version against a CVE's configurations.

    confirmed: a vulnerable CPE for this product covers the version. possible: it does, but only
    inside an AND configuration (typically "and running on a given OS"), which the site's
    fingerprint cannot confirm.
    """
    best: tuple[str, str, str | None] | None = None
    for cfg in configurations:
        anded = (cfg.get("operator") or "").upper() == "AND"
        for node in cfg.get("nodes") or []:
            for m in node.get("matches") or []:
                parts = cpe_fields(m.get("criteria") or "")
                if len(parts) < 6 or parts[3].lower() != vendor or parts[4].lower() != product:
                    continue
                if not covers(version, parts[5], m):
                    continue
                verdict = "possible" if anded else "confirmed"
                if best is None or (verdict == "confirmed" and best[0] == "possible"):
                    best = (verdict, range_text(parts[5], m), m.get("versionEndExcluding"))
    return best or (None, "", None)


def cpe_fields(cpe: str) -> list[str]:
    """Split a CPE 2.3 string on unescaped colons."""
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", cpe)]


def covers(version: str, cpe_version: str, m: dict) -> bool:
    """Does one cpeMatch entry include this version?"""
    if cpe_version in ("-", ""):
        return False
    if cpe_version != "*":
        return compare(version, cpe_version) == 0
    bounds = (("versionStartIncluding", 1, True), ("versionStartExcluding", 1, False),
              ("versionEndIncluding", -1, True), ("versionEndExcluding", -1, False))
    for key, direction, inclusive in bounds:
        if key not in m:
            continue
        c = compare(version, m[key])
        if c is None:
            return False  # cannot order these two versions, so make no claim
        # direction 1 is a lower bound (version >= bound); -1 an upper bound (version <= bound)
        if c * direction < 0 or (c == 0 and not inclusive):
            return False
    return True


def range_text(cpe_version: str, m: dict) -> str:
    if cpe_version not in ("*", "-"):
        return f"={cpe_version}"
    ops = (("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
           ("versionEndIncluding", "<="), ("versionEndExcluding", "<"))
    text = " ".join(f"{op}{m[k]}" for k, op in ops if k in m)
    return text or "all versions"


# --------------------------------------------------------------------------- #
# loose version comparison
# --------------------------------------------------------------------------- #

PRERELEASE = ("alpha", "beta", "rc", "pre", "preview", "dev", "snapshot")
_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def _key(v: str) -> tuple | None:
    """Sortable key: numeric parts, then 0 for a prerelease or 1 for a release, then the tail.

    Handles 1.2, 1.2.3.4, 2.4.41-rc1 and OpenSSL-style 1.0.2k. None when there is no number.
    """
    tokens = _TOKEN.findall(v.strip().lower().lstrip("v"))
    nums: list[int] = []
    i = 0
    while i < len(tokens) and tokens[i].isdigit():
        nums.append(int(tokens[i]))
        i += 1
    if not nums:
        return None
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()  # 1.2 == 1.2.0
    tail = tokens[i:]
    phase = 0 if tail and tail[0] in PRERELEASE else 1
    return (tuple(nums), phase, tuple(tail))


def compare(a: str, b: str) -> int | None:
    """-1, 0 or 1; None when either side has no comparable number. Never raises."""
    try:
        ka, kb = _key(a), _key(b)
    except (AttributeError, ValueError):
        return None
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


# --------------------------------------------------------------------------- #
# disk cache
# --------------------------------------------------------------------------- #

def _read(path: Path) -> list[dict] | None:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else None
    except (OSError, ValueError):
        return None


def _write(path: Path, data: list[dict]) -> None:
    threat._write_cache(path, data)
