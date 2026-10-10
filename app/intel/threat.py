"""Exploitation signals per CVE: the CISA KEV catalog and FIRST EPSS scores.

Both feeds key on CVE IDs, and OSV advisories carry them as aliases, so no fingerprinting is
needed. Responses are cached on disk with a TTL. A feed that fails degrades to "unavailable" for
that signal (a stale cache is used before giving up); it never raises into a run.
"""

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from app import config
from app.schema import Emit, ThreatIntel

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = Path("data/cache/intel")
KEV_TTL = 12 * 3600
EPSS_TTL = 24 * 3600
KEV_MAX_BYTES = 16 * 1024 * 1024
EPSS_MAX_BYTES = 1024 * 1024
EPSS_BATCH = 50  # ~15 chars per CVE keeps the query string well under common URL limits
TIMEOUT = 20.0
USER_AGENT = "stackwatch-agent/0.1 (passive)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class IntelTable:
    """Looked-up signals. A None map means that feed was unavailable, {} means it answered empty."""

    kev: dict[str, dict] | None = None
    epss: dict[str, dict] | None = None


def cve_ids(advisory_id: str, aliases: list[str]) -> list[str]:
    """CVE IDs for an advisory: its own ID when it is one, plus CVE aliases, upper-cased."""
    out: list[str] = []
    for x in [advisory_id, *aliases]:
        x = (x or "").strip().upper()
        if CVE_RE.match(x) and x not in out:
            out.append(x)
    return out


def lookup(cves: list[str], emit: Emit) -> IntelTable:
    """Fetch (or read from cache) KEV and EPSS data for these CVEs."""
    cves = sorted({c.upper() for c in cves if CVE_RE.match(c or "")})
    if not cves:
        return IntelTable(kev={}, epss={})
    try:
        table = IntelTable(kev=_load_kev(emit), epss=_load_epss(cves, emit))
    except Exception as e:  # noqa: BLE001 - a feed problem must never fail a run
        emit("intel", "warn", f"Threat intel lookup failed: {e}", None)
        return IntelTable()
    listed = sum(1 for c in cves if table.kev and c in table.kev)
    emit("intel", "info", f"Threat intel for {len(cves)} CVEs: {listed} in CISA KEV"
         + ("" if table.kev is not None else " (KEV unavailable)")
         + ("" if table.epss is not None else " (EPSS unavailable)"), None)
    return table


def intel_for(cves: list[str], table: IntelTable) -> ThreatIntel:
    """Collapse the table to one finding's signals: KEV if any CVE is listed, highest EPSS."""
    cves = sorted({c.upper() for c in cves})
    if not cves:
        return ThreatIntel(status="no-cve")
    if table.kev is None and table.epss is None:
        return ThreatIntel(status="unavailable", cves=cves)
    out = ThreatIntel(status="ok" if table.kev is not None and table.epss is not None
                      else "partial", cves=cves)
    listed = [(c, table.kev[c]) for c in cves if table.kev and c in table.kev]
    if listed:
        out.kev = True
        # The earliest due date is the binding one when several CVEs are listed.
        entry = min((e for _, e in listed), key=lambda e: e.get("due") or "9999")
        out.kev_date_added = entry.get("added")
        out.kev_due_date = entry.get("due")
        out.kev_ransomware = any(e.get("ransomware") for _, e in listed)
    scored = [table.epss[c] for c in cves if table.epss and c in table.epss]
    if scored:
        top = max(scored, key=lambda e: e["epss"])
        out.epss, out.epss_percentile = top["epss"], top["percentile"]
    return out


# --------------------------------------------------------------------------- #
# feeds
# --------------------------------------------------------------------------- #

def _load_kev(emit: Emit) -> dict[str, dict] | None:
    path = CACHE_DIR / "kev.json"
    cached = _read_cache(path)
    if cached is not None and _fresh(path, KEV_TTL):
        return cached
    if not config.CACHE_ONLY:
        try:
            raw = json.loads(_http_get(KEV_URL, None, KEV_MAX_BYTES))
            data = {}
            for v in raw.get("vulnerabilities", []):
                cve = str(v.get("cveID", "")).upper()
                if CVE_RE.match(cve):
                    data[cve] = {
                        "added": v.get("dateAdded"),
                        "due": v.get("dueDate"),
                        "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                    }
            if data:
                _write_cache(path, data)
                return data
            raise ValueError("catalog had no entries")
        except Exception as e:  # noqa: BLE001 - degrade to the stale cache
            emit("intel", "warn", f"CISA KEV fetch failed: {e}", None)
    return cached  # stale beats nothing; None when there is no cache at all


def _load_epss(cves: list[str], emit: Emit) -> dict[str, dict] | None:
    path = CACHE_DIR / "epss.json"
    cache = _read_cache(path) or {}
    now = time.time()
    fresh = {c: e for c, e in cache.items() if now - e.get("fetched", 0) < EPSS_TTL}
    missing = [c for c in cves if c not in fresh]
    failed = False
    if missing and not config.CACHE_ONLY:
        for i in range(0, len(missing), EPSS_BATCH):
            batch = missing[i:i + EPSS_BATCH]
            try:
                body = json.loads(_http_get(EPSS_URL, {"cve": ",".join(batch)}, EPSS_MAX_BYTES))
                for row in body.get("data", []):
                    cve = str(row.get("cve", "")).upper()
                    if cve in batch:
                        cache[cve] = {"epss": float(row["epss"]),
                                      "percentile": float(row["percentile"]),
                                      "date": row.get("date"), "fetched": now}
                # A CVE with no EPSS row is cached as scoreless so it is not re-asked every run.
                for c in batch:
                    cache.setdefault(c, {"epss": None, "percentile": None, "fetched": now})
            except Exception as e:  # noqa: BLE001 - degrade to the cache
                failed = True
                emit("intel", "warn", f"EPSS fetch failed: {e}", None)
        _write_cache(path, cache)
    have = {c: cache[c] for c in cves if c in cache and cache[c].get("epss") is not None}
    answered = [c for c in cves if c in cache]  # fresh, fetched now, or stale as a fallback
    if failed and not answered:
        return None
    if config.CACHE_ONLY and not answered:
        return None
    return have


def _http_get(url: str, params: dict | None, max_bytes: int) -> bytes:
    """GET a fixed, trusted feed over HTTPS with a hard size cap. No redirects are followed."""
    body = bytearray()
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                      headers={"User-Agent": USER_AGENT}) as client, \
            client.stream("GET", url, params=params) as r:
        r.raise_for_status()
        for chunk in r.iter_bytes():
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ValueError(f"response over {max_bytes} bytes")
    return bytes(body)


def _fresh(path: Path, ttl: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime < ttl
    except OSError:
        return False


def _read_cache(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _write_cache(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(path)
    except OSError:
        pass
