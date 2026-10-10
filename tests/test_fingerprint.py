"""Passive version fingerprinting from headers, HTML and bundle banners (no network)."""

from pathlib import Path

import pytest

from app.recon import fingerprint, website
from app.recon.fingerprint import fingerprint_web, is_release
from app.recon.kb import FetchedPage, KnowledgeBase
from app.recon.stack import derive_stack

FIX = Path(__file__).parent / "fixtures" / "fingerprint"
SITE = "https://acme.example/"


def _web(fixture: str, headers: dict | None = None) -> dict:
    html = (FIX / fixture).read_text()
    page = FetchedPage(url=SITE, final_url=SITE, host="acme.example", status=200,
                       headers=headers or {}, html=html)
    return website.extract_web(page, website.parse_html(html), "acme.example")


def _by_name(fps):
    return {f.name: f for f in fps}


@pytest.mark.parametrize("value,ok", [
    ("3.5.1", True), ("1.12", True), ("5.3.0-beta.1", True), ("0.120.4", True),
    ("3f9a2c1d", False), ("1618933200", False), ("20240115", False), ("2024.01.15", False),
    ("c6aec9a8d4e5a5d543a1", False), ("", False), (None, False), ("5", False),
])
def test_is_release_rejects_hashes_and_stamps(value, ok):
    assert is_release(value) is ok


def test_wordpress_page_versions():
    got = _by_name(fingerprint_web(_web("wordpress_home.html")))
    wp = got["WordPress"]
    assert wp.version == "6.4.2" and wp.category == "cms"
    # The generator meta and the core ?ver= agree, and the explicit meta is listed once.
    assert "Generator meta" in wp.evidence or "?ver=6.4.2" in wp.evidence

    assert got["jQuery"].version == "3.7.1" and got["jQuery"].confidence == "medium"
    assert got["jQuery"].npm == "jquery"
    assert got["Bootstrap"].version == "5.3.0" and got["Bootstrap"].confidence == "high"
    assert "bootstrap@5.3.0" in got["Bootstrap"].evidence
    assert got["Lodash"].version == "4.17.21" and got["Lodash"].confidence == "high"
    assert got["Moment.js"].version == "2.29.4"
    assert got["jQuery UI"].version in ("1.13.2", "1.12.1")


def test_wordpress_plugin_and_theme_are_low_confidence():
    got = _by_name(fingerprint_web(_web("wordpress_home.html")))
    plugin = got["WordPress plugin contact-form-7"]
    assert plugin.version == "5.8.4" and plugin.confidence == "low"
    theme = got["WordPress theme bakery"]
    assert theme.version == "2.0.1" and theme.confidence == "low"


def test_wordpress_core_version_ignores_vendored_and_hash_assets():
    """jquery-migrate 3.4.1 under /wp-includes/js/jquery/ must not become the WordPress version."""
    web = {"final_url": SITE, "generator": None, "scripts": [
        SITE + "wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1",
        SITE + "wp-includes/js/dist/hooks.min.js?ver=c6aec9a8d4e5a5d543a1"]}
    assert "WordPress" not in _by_name(fingerprint_web(web))


def test_conflicting_core_versions_lower_confidence():
    web = {"final_url": SITE, "stylesheets": [
        SITE + "wp-includes/css/a.css?ver=6.4.2", SITE + "wp-includes/css/b.css?ver=6.4.2",
        SITE + "wp-includes/css/c.css?ver=5.1"]}
    wp = _by_name(fingerprint_web(web))["WordPress"]
    assert wp.version == "6.4.2" and wp.confidence == "low" and "5.1" in wp.evidence


def test_cache_busting_strings_do_not_become_versions():
    fps = fingerprint_web(_web("cache_busting_home.html"))
    versioned = [(f.name, f.version) for f in fps if f.version]
    assert versioned == [("Hugo", "0.120.4")]  # only the explicit generator meta
    names = {f.name for f in fps}
    assert not names & {"jQuery", "Bootstrap", "React"}  # no version, so no claim


def test_unknown_library_filename_is_skipped_not_guessed():
    web = {"final_url": SITE, "scripts": [SITE + "js/unknownlib-4.2.1.min.js",
                                          SITE + "js/chunk-2.1.9-abcdef.js"]}
    assert fingerprint_web(web) == []


def test_query_version_on_known_library_is_low_outside_wordpress():
    web = {"final_url": SITE, "scripts": [SITE + "js/jquery.min.js?ver=1.4"]}
    jq = _by_name(fingerprint_web(web))["jQuery"]
    assert jq.version == "1.4" and jq.confidence == "low"


def test_filename_beats_query_string():
    web = {"final_url": SITE, "scripts": [SITE + "js/jquery-3.5.1.min.js?ver=9.9"]}
    jq = _by_name(fingerprint_web(web))["jQuery"]
    assert jq.version == "3.5.1" and jq.confidence == "medium"


@pytest.mark.parametrize("server,name,version", [
    ("nginx/1.18.0", "nginx", "1.18.0"),
    ("Apache/2.4.41 (Ubuntu)", "Apache", "2.4.41"),
    ("Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"),
    ("nginx", "nginx", None),
    ("Apache/2", "Apache", None),
    ("cloudflare", "cloudflare", None),
])
def test_server_header(server, name, version):
    fps = fingerprint_web({"final_url": SITE, "headers": {"server": server}})
    srv = next(f for f in fps if f.category == "web-server")
    assert (srv.name, srv.version) == (name, version)
    assert srv.evidence.startswith("Server: ")


def test_powered_by_and_aspnet_headers():
    fps = _by_name(fingerprint_web({"final_url": SITE, "headers": {
        "x-powered-by": "PHP/7.4.3", "x-aspnet-version": "4.0.30319"}}))
    assert fps["PHP"].version == "7.4.3" and fps["PHP"].confidence == "medium"
    assert fps["ASP.NET"].version == "4.0.30319"
    express = _by_name(fingerprint_web({"final_url": SITE, "headers": {"x-powered-by": "Express"}}))
    assert express["Express"].version is None and express["Express"].npm == "express"


def test_generator_forms():
    def gen(v):
        return fingerprint_web({"final_url": SITE, "generator": v})[0]
    assert (gen("Drupal 10 (https://www.drupal.org)").name,
            gen("Drupal 10 (https://www.drupal.org)").version) == ("Drupal", "10")
    assert gen("Joomla! - Open Source Content Management").version is None
    assert gen("Ghost 5.75").version == "5.75"
    assert gen("Hugo 20240115").version is None


def test_bundle_banner_reads_the_leading_comment_only():
    js = (FIX / "bundle_banner.js").read_text()
    found = fingerprint.bundle_banners(js, SITE + "app.js")
    assert [(b["name"], b["version"]) for b in found] == [("jQuery", "3.5.1")]  # not Bootstrap
    late = "x" * 4000 + "/*! jQuery v3.5.1 */"
    assert fingerprint.bundle_banners(late, SITE + "app.js") == []


def test_banner_variants():
    cases = {
        "/*!\n * jQuery JavaScript Library v1.12.4\n */": ("jQuery", "1.12.4"),
        "/*!\n * Bootstrap v4.6.0 (https://getbootstrap.com/)\n */": ("Bootstrap", "4.6.0"),
        "/** @license React v17.0.2\n * react.production.min.js\n */": ("React", "17.0.2"),
        "/** @license React v17.0.2\n * react-dom.production.min.js\n */":
            ("React DOM", "17.0.2"),
        "//! moment.js\n//! version : 2.29.4\n": ("Moment.js", "2.29.4"),
        "/*! Vue.js v2.6.14 */": ("Vue.js", "2.6.14"),
    }
    for js, want in cases.items():
        got = fingerprint.bundle_banners(js, "u")
        assert [(b["name"], b["version"]) for b in got] == [want], js


def test_derive_stack_records_versions_with_evidence():
    kb = KnowledgeBase(domain="acme.example", run_id="r", target_id="t")
    kb.web.update(_web("wordpress_home.html", {"server": "nginx/1.18.0",
                                               "x-powered-by": "PHP/7.4.3"}))
    kb.web["spa"] = {"bundles": [], "banners": [{
        "key": "vue", "name": "Vue.js", "npm": "vue", "version": "2.6.14",
        "banner": "/*! Vue.js v2.6.14", "url": SITE + "app.js"}]}
    derive_stack(kb)
    got = {t.name: t for t in kb.stack}
    assert got["nginx"].version == "1.18.0" and got["nginx"].confidence == "high"
    assert got["PHP"].version == "7.4.3"
    assert got["WordPress"].version == "6.4.2" and got["WordPress"].evidence
    assert got["Vue.js"].version == "2.6.14" and got["Vue.js"].source.endswith("app.js")
    assert got["Vue.js"].npm == "vue" and "banner" in got["Vue.js"].evidence.lower()


def test_discover_public_turns_confident_library_versions_into_osv_items(monkeypatch):
    from app.discovery import public
    from app.schema import Target

    html = (FIX / "wordpress_home.html").read_text()
    page = FetchedPage(url=SITE, final_url=SITE, host="acme.example", status=200,
                       headers={"server": "nginx/1.18.0"}, html=html)

    def fake_build(kb, emit):
        kb.web.update(website.extract_web(page, website.parse_html(html), kb.domain))
        return [page]

    from app.recon import runner
    monkeypatch.setattr(runner, "build_knowledge", fake_build)
    monkeypatch.setattr(runner, "save", lambda *a, **k: None)
    from app.agent import research
    monkeypatch.setattr(research, "research", lambda *a, **k: None)
    items = public.discover_public(
        Target(target_id="t_acme", kind="public", name="acme", domain="acme.example"), "r1",
        lambda *a: None)
    got = {i.package: i for i in items}
    assert got["bootstrap"].version == "5.3.0" and got["bootstrap"].confidence == "high"
    assert got["lodash"].version == "4.17.21"
    assert "jquery" in got and got["jquery"].version == "3.7.1"
    assert "wordpress" not in got  # not an npm package; stays in the stack list only
