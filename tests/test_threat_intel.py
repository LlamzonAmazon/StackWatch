"""KEV and EPSS enrichment: offline, with the HTTP layer mocked and the cache in a temp dir."""

from pathlib import Path

import pytest

from app import config
from app.correlate.score import intel_risk_boost, score_intel
from app.intel import threat
from app.schema import ThreatIntel

FIX = Path(__file__).parent / "fixtures" / "intel"
KEV = (FIX / "kev_sample.json").read_bytes()
EPSS = (FIX / "epss_sample.json").read_bytes()
log4j, lodash, hot = "CVE-2021-44228", "CVE-2019-10744", "CVE-2024-1111"


class Feeds:
    """Stands in for threat._http_get; records calls, can fail per feed."""

    def __init__(self):
        self.calls: list[str] = []
        self.down: set[str] = set()

    def __call__(self, url, params, max_bytes):
        feed = "kev" if url == threat.KEV_URL else "epss"
        self.calls.append(feed)
        if feed in self.down:
            raise ConnectionError(f"{feed} down")
        return KEV if feed == "kev" else EPSS


@pytest.fixture
def feeds(tmp_path, monkeypatch):
    f = Feeds()
    monkeypatch.setattr(threat, "CACHE_DIR", tmp_path / "intel")
    monkeypatch.setattr(threat, "_http_get", f)
    monkeypatch.setattr(config, "CACHE_ONLY", False)
    return f


def emit(*_):
    pass


def test_cve_ids_join_by_alias_and_ignore_non_cves():
    assert threat.cve_ids("GHSA-aaaa", ["CVE-2021-44228", "GHSA-bbbb", "cve-2019-10744"]) == [
        log4j, lodash]
    assert threat.cve_ids("CVE-2021-44228", ["CVE-2021-44228"]) == [log4j]
    assert threat.cve_ids("GHSA-aaaa", []) == []
    assert threat.cve_ids("GHSA-aaaa", ["CVE-bad", "../CVE-2021-44228"]) == []


def test_lookup_joins_kev_and_epss(feeds):
    table = threat.lookup([log4j, lodash, hot], emit)
    i = threat.intel_for([log4j], table)
    assert i.status == "ok" and i.kev is True
    assert (i.kev_date_added, i.kev_due_date, i.kev_ransomware) == (
        "2021-12-10", "2021-12-24", True)
    assert i.epss == pytest.approx(0.99999) and i.epss_percentile == pytest.approx(1.0)
    j = threat.intel_for([lodash], table)
    assert j.kev and j.kev_ransomware is False and j.epss == pytest.approx(0.012)
    k = threat.intel_for([hot], table)
    assert k.kev is False and k.epss == pytest.approx(0.64)


def test_worst_case_across_an_advisorys_cves(feeds):
    table = threat.lookup([lodash, hot], emit)
    i = threat.intel_for([lodash, hot], table)
    assert i.kev and i.epss == pytest.approx(0.64)


def test_missing_cve_alias_makes_no_requests(feeds):
    table = threat.lookup([], emit)
    assert feeds.calls == []
    i = threat.intel_for([], table)
    assert i.status == "no-cve" and not i.kev and i.epss is None


def test_cve_not_in_either_feed_is_ok_but_empty(feeds):
    i = threat.intel_for(["CVE-2000-0001"], threat.lookup(["CVE-2000-0001"], emit))
    assert i.status == "ok" and not i.kev and i.epss is None


def test_feed_outage_degrades_to_unavailable(feeds):
    feeds.down = {"kev", "epss"}
    table = threat.lookup([log4j], emit)  # must not raise
    i = threat.intel_for([log4j], table)
    assert i.status == "unavailable" and not i.kev and i.cves == [log4j]


def test_single_feed_outage_is_partial(feeds):
    feeds.down = {"epss"}
    i = threat.intel_for([log4j], threat.lookup([log4j], emit))
    assert i.status == "partial" and i.kev and i.epss is None


def test_second_lookup_is_served_from_cache(feeds):
    threat.lookup([log4j, lodash], emit)
    assert sorted(feeds.calls) == ["epss", "kev"]
    feeds.down = {"kev", "epss"}
    i = threat.intel_for([log4j], threat.lookup([log4j, lodash], emit))
    assert i.status == "ok" and i.kev and len(feeds.calls) == 2


def test_cache_only_lookup_never_fetches(feeds):
    """The report route reads with cache_only, so a GET cannot cause outbound traffic."""
    cold = threat.intel_for([log4j], threat.lookup([log4j], emit, cache_only=True))
    assert feeds.calls == [] and cold.status == "unavailable"
    threat.lookup([log4j], emit)
    warm = threat.intel_for([log4j], threat.lookup([log4j], emit, cache_only=True))
    assert len(feeds.calls) == 2 and warm.status == "ok" and warm.kev


def test_stale_cache_is_used_when_the_refresh_fails(feeds, monkeypatch):
    threat.lookup([log4j], emit)
    monkeypatch.setattr(threat, "KEV_TTL", -1)
    monkeypatch.setattr(threat, "EPSS_TTL", -1)
    feeds.down = {"kev", "epss"}
    i = threat.intel_for([log4j], threat.lookup([log4j], emit))
    assert i.status == "ok" and i.kev and i.epss is not None


def test_cache_only_never_hits_the_network(feeds, monkeypatch):
    monkeypatch.setattr(config, "CACHE_ONLY", True)
    i = threat.intel_for([log4j], threat.lookup([log4j], emit))
    assert feeds.calls == [] and i.status == "unavailable"


def test_oversize_response_degrades(feeds, monkeypatch):
    def big(url, params, max_bytes):
        raise ValueError("response over limit")

    monkeypatch.setattr(threat, "_http_get", big)
    assert threat.intel_for([log4j], threat.lookup([log4j], emit)).status == "unavailable"


def test_malformed_feed_json_degrades(feeds, monkeypatch):
    monkeypatch.setattr(threat, "_http_get", lambda *a: b"<html>not json</html>")
    assert threat.intel_for([log4j], threat.lookup([log4j], emit)).status == "unavailable"


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #

KEV_INTEL = ThreatIntel(status="ok", cves=[log4j], kev=True, epss=0.99, epss_percentile=1.0)
EPSS_INTEL = ThreatIntel(status="ok", cves=[hot], epss=0.64, epss_percentile=0.98)
QUIET = ThreatIntel(status="ok", cves=[lodash], epss=0.01, epss_percentile=0.5)


def test_scoring_order_kev_over_epss_over_nothing():
    assert intel_risk_boost(KEV_INTEL) > intel_risk_boost(EPSS_INTEL) > intel_risk_boost(QUIET) == 0
    assert intel_risk_boost(None) == 0
    assert intel_risk_boost(ThreatIntel(status="unavailable")) == 0


def test_severity_bumps_one_level_and_caps():
    assert score_intel("medium", [], KEV_INTEL, "exposed")[0] == "high"
    assert score_intel("medium", [], EPSS_INTEL, "called")[0] == "high"
    assert score_intel("critical", [], KEV_INTEL, "exposed")[0] == "critical"
    level, reasons = score_intel("medium", ["r"], QUIET, "exposed")
    assert level == "medium" and reasons == ["r"]


def test_unreachable_package_is_not_raised_but_says_why():
    level, reasons = score_intel("low", [], KEV_INTEL, "installed")
    assert level == "low" and "KEV" in reasons[-1] and "no change" in reasons[-1]
