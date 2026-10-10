"""Passive version fingerprinting from what recon already fetched.

Inputs are the home page response headers, the parsed HTML (meta generator, script and
stylesheet URLs) and the leading comment of any JS bundle recon already downloaded. Nothing here
makes a request. Only products in the curated tables are named, and a version must look like a
release number: content hashes, timestamps and date stamps used for cache busting are rejected,
so an unknown file or an odd query string yields no version rather than a wrong one.
"""

import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

# A release number: 1.2, 1.2.3, 1.2.3.4, optional prerelease. A major of 100 or more is a date or
# a build stamp (20240115), not a release of anything we fingerprint.
VERSION = r"\d{1,3}(?:\.\d{1,5}){1,3}(?:-(?:alpha|beta|rc)[.\d]*)?"
VERSION_RE = re.compile(rf"^{VERSION}$")

# Known JS libraries: url/banner token -> (display name, npm package).
LIBS = {
    "jquery": ("jQuery", "jquery"),
    "jquery-ui": ("jQuery UI", "jquery-ui"),
    "bootstrap": ("Bootstrap", "bootstrap"),
    "lodash": ("Lodash", "lodash"),
    "underscore": ("Underscore.js", "underscore"),
    "moment": ("Moment.js", "moment"),
    "react": ("React", "react"),
    "react-dom": ("React DOM", "react-dom"),
    "vue": ("Vue.js", "vue"),
    "angular": ("AngularJS", "angular"),
    "d3": ("D3", "d3"),
    "three": ("Three.js", "three"),
    "axios": ("Axios", "axios"),
    "popper": ("Popper", "popper.js"),
    "chart": ("Chart.js", "chart.js"),
    "backbone": ("Backbone.js", "backbone"),
    "handlebars": ("Handlebars", "handlebars"),
    "swiper": ("Swiper", "swiper"),
    "gsap": ("GSAP", "gsap"),
    "alpine": ("Alpine.js", "alpinejs"),
    "htmx": ("htmx", "htmx.org"),
    "select2": ("Select2", "select2"),
}
# Spellings that map to a LIBS key.
LIB_ALIASES = {
    "jquery.ui": "jquery-ui", "jqueryui": "jquery-ui", "popper.js": "popper",
    "chart.js": "chart", "chartjs": "chart", "backbone.js": "backbone", "vue.js": "vue",
    "angularjs": "angular", "alpinejs": "alpine", "htmx.org": "htmx", "moment.js": "moment",
    "three.js": "three", "underscore.js": "underscore", "underscore-min": "underscore",
    "d3.js": "d3", "lodash.js": "lodash",
}
# Packages published under their own name on jsDelivr and unpkg.
NPM_PACKAGES = {v[1]: k for k, v in LIBS.items()} | {"@popperjs/core": "popper"}

# name-1.2.3(.min).js and name.1.2.3.js; the name must be a known library.
FILE_VERSION = re.compile(
    rf"(?P<name>[a-z][a-z0-9.]*?(?:-ui)?)[-.@_]v?(?P<ver>{VERSION})(?:[.-]min)?\.(?:m?js|css)$",
    re.IGNORECASE)
# CDN paths that carry the version as a directory.
CDNJS_PATH = re.compile(rf"/ajax/libs/(?P<name>[a-z0-9.\-]+)/(?P<ver>{VERSION})/", re.IGNORECASE)
PKG_AT_VERSION = re.compile(
    rf"/(?:npm/)?(?P<name>@?[a-z0-9._\-]+(?:/[a-z0-9._\-]+)?)@(?P<ver>{VERSION})(?:/|$)",
    re.IGNORECASE)
# The leading comment of a bundle: /*! jQuery v3.5.1 | ... and /** Bootstrap v4.6.0 ...
BANNER = re.compile(
    r"(?://!|/\*[!*]?)\s*(?:\*\s*)?(?:@license\s+)?"
    r"(?P<name>jQuery UI|jQuery|Bootstrap|Lodash|Underscore\.js|Moment\.js|Vue\.js|React|"
    r"AngularJS|Chart\.js|Backbone\.js|Handlebars|Popper\.js|Axios|Three\.js|D3)"
    rf"(?:\s+JavaScript Library|\s+JS)?\s+(?:v|version\s*:?\s*)?(?P<ver>{VERSION})\b",
    re.IGNORECASE)
MOMENT_BANNER = re.compile(rf"//!\s*moment\.js\s*\n\s*//!\s*version\s*:\s*(?P<ver>{VERSION})",
                           re.IGNORECASE)
BANNER_WINDOW = 3000  # a license banner is the first thing in a file

QUERY_KEYS = ("ver", "v", "version")
GENERATOR = re.compile(rf"^(?P<name>[A-Za-z][\w.!+ -]*?)\s+v?(?P<ver>{VERSION}|\d{{1,3}})\b")
TOKEN = re.compile(rf"^(?P<name>[A-Za-z][\w.+-]*)/(?P<ver>{VERSION}|\d{{1,3}})\b")
WP_PLUGIN = re.compile(r"/wp-content/plugins/(?P<slug>[a-z0-9_-]+)/", re.IGNORECASE)
WP_THEME = re.compile(r"/wp-content/themes/(?P<slug>[a-z0-9_-]+)/", re.IGNORECASE)
MAX_WP_EXTRAS = 10


@dataclass
class Fingerprint:
    name: str
    category: str
    version: str | None
    confidence: str  # high, medium, low
    evidence: str
    source: str
    npm: str | None = None


def is_release(v: str | None) -> bool:
    """True for a plausible release number. Hashes, timestamps and date stamps are not."""
    if not v or not VERSION_RE.match(v):
        return False
    return int(v.split(".")[0].split("-")[0]) < 100


def _is_major_only(v: str) -> bool:
    return v.isdigit() and int(v) < 100


def fingerprint_web(web: dict) -> list[Fingerprint]:
    """Versioned technologies from kb.web: headers, generator meta, assets and bundle banners."""
    site = web.get("final_url") or ""
    headers = dict(web.get("headers") or {})
    for key, header in (("server", "server"), ("powered_by", "x-powered-by")):
        if web.get(key):
            headers.setdefault(header, web[key])
    out = _from_headers(headers, site)
    out += _from_generator(web.get("generator"), "Generator meta", site, "cms")
    assets = list(web.get("scripts") or []) + list(web.get("stylesheets") or [])
    out += _from_assets(assets, site)
    for b in (web.get("spa") or {}).get("banners") or []:
        out.append(Fingerprint(
            name=b["name"], category="js-library", version=b["version"], confidence="high",
            evidence=f"License banner: {b['banner']}", source=b.get("url") or site,
            npm=b.get("npm")))
    return out


# --------------------------------------------------------------------------- #
# headers and generator
# --------------------------------------------------------------------------- #

def _from_headers(headers: dict, site: str) -> list[Fingerprint]:
    h = {k.lower(): str(v) for k, v in headers.items()}
    out: list[Fingerprint] = []
    server = h.get("server", "")
    if server:
        m = TOKEN.match(server)
        name, ver = (m["name"], m["ver"]) if m else (server.split("/")[0].split()[0], None)
        ver = ver if ver and "." in ver else None  # "Apache/2" names no release
        out.append(Fingerprint(name=name, category="web-server", version=ver, confidence="high",
                               evidence=f"Server: {server[:80]}", source=site))
    powered = h.get("x-powered-by", "")
    if powered:
        m = TOKEN.match(powered)
        name, ver = (m["name"], m["ver"]) if m else (powered.split("/")[0].strip(), None)
        ver = ver if ver and "." in ver else None
        npm = "express" if name.lower() == "express" else None
        out.append(Fingerprint(name=name, category="framework", version=ver, confidence="medium",
                               evidence=f"X-Powered-By: {powered[:80]}", source=site, npm=npm))
    aspnet = h.get("x-aspnet-version", "")
    if aspnet and VERSION_RE.match(aspnet.strip()):
        out.append(Fingerprint(name="ASP.NET", category="framework", version=aspnet.strip(),
                               confidence="medium", evidence=f"X-AspNet-Version: {aspnet}",
                               source=site))
    out += _from_generator(h.get("x-generator"), "X-Generator", site, "cms")
    return out


def _from_generator(value: str | None, label: str, site: str, category: str) -> list[Fingerprint]:
    if not value:
        return []
    value = value.strip()
    m = GENERATOR.match(value)
    if m and (is_release(m["ver"]) or _is_major_only(m["ver"])):
        return [Fingerprint(name=m["name"].strip(), category=category, version=m["ver"],
                            confidence="high", evidence=f"{label}: {value[:80]}", source=site)]
    # No usable version: keep the product name from the first words, as before.
    return [Fingerprint(name=value[:60], category=category, version=None, confidence="high",
                        evidence=f"{label}: {value[:80]}", source=site)]


# --------------------------------------------------------------------------- #
# asset URLs
# --------------------------------------------------------------------------- #

def _from_assets(urls: list[str], site: str) -> list[Fingerprint]:
    libs: dict[str, Fingerprint] = {}
    wp_core: Counter = Counter()
    wp_core_src: dict[str, str] = {}
    extras: dict[str, Fingerprint] = {}
    for url in urls:
        parts = urlsplit(url)
        path, query = parts.path, parse_qs(parts.query)
        query_ver = next((query[k][0] for k in QUERY_KEYS if k in query), None)
        hit = _lib_from_path(path)
        if hit:
            key, ver, how, conf = hit
            if ver is None and is_release(query_ver):
                # A bare query value is whatever the site author set; WordPress core is the
                # exception because it stamps its own bundled library versions.
                ver, how = query_ver, f"?{_qk(query, query_ver)}={query_ver}"
                conf = "medium" if "/wp-includes/" in path else "low"
            if ver and (key not in libs or _rank(conf) > _rank(libs[key].confidence)):
                name, npm = LIBS[key]
                libs[key] = Fingerprint(
                    name=name, category="js-library", version=ver, confidence=conf,
                    evidence=f"{how} in {_tail(url)}", source=url, npm=npm)
            continue
        # Vendored libraries under /wp-includes/js/<dir>/ (jquery-migrate, tinymce, ...) carry
        # their own versions, not WordPress's.
        if ("/wp-includes/" in path and not re.search(r"/wp-includes/js/[^/]+/", path)
                and is_release(query_ver)):
            wp_core[query_ver] += 1
            wp_core_src.setdefault(query_ver, url)
        for rx, label, cat in ((WP_PLUGIN, "WordPress plugin", "cms-plugin"),
                               (WP_THEME, "WordPress theme", "cms-theme")):
            m = rx.search(path)
            if m and is_release(query_ver) and len(extras) < MAX_WP_EXTRAS:
                name = f"{label} {m['slug']}"
                # ?ver= on a plugin or theme asset is set by its author; it often tracks the
                # release but is not guaranteed to.
                extras.setdefault(name, Fingerprint(
                    name=name, category=cat, version=query_ver, confidence="low",
                    evidence=f"?ver={query_ver} on {_tail(url)}", source=url))
    out = list(libs.values()) + list(extras.values())
    if wp_core:
        ver, n = wp_core.most_common(1)[0]
        agreed = len(wp_core) == 1
        out.append(Fingerprint(
            name="WordPress", category="cms", version=ver,
            confidence="medium" if agreed else "low",
            evidence=f"?ver={ver} on {n} core asset(s) under /wp-includes/"
                     + ("" if agreed else f" (other values seen: {', '.join(sorted(set(wp_core) - {ver}))})"),
            source=wp_core_src[ver]))
    return out


def _lib_from_path(path: str) -> tuple[str, str | None, str, str] | None:
    """(library key, version or None, how it was found, confidence) for a known library file."""
    m = CDNJS_PATH.search(path)
    if m and (key := _lib_key(m["name"])):
        return key, m["ver"], f"CDN path /ajax/libs/{m['name']}/{m['ver']}/", "high"
    m = PKG_AT_VERSION.search(path)
    if m:
        key = NPM_PACKAGES.get(m["name"].lower()) or _lib_key(m["name"])
        if key:
            return key, m["ver"], f"Package pin {m['name']}@{m['ver']}", "high"
    base = path.rsplit("/", 1)[-1]
    m = FILE_VERSION.search(base)
    if m and (key := _lib_key(m["name"])):
        return key, m["ver"], f"Filename {base}", "medium"
    stem = re.sub(r"(?:[.-]min)?\.(?:m?js|css)$", "", base, flags=re.IGNORECASE)
    if (key := _lib_key(stem)) and base != stem:
        return key, None, "", "low"  # known library, no version in the name
    return None


def _lib_key(token: str) -> str | None:
    t = token.lower().strip(".-_")
    t = LIB_ALIASES.get(t, t)
    return t if t in LIBS else None


def _qk(query: dict, value: str) -> str:
    return next(k for k in QUERY_KEYS if k in query and query[k][0] == value)


def _rank(conf: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}[conf]


def _tail(url: str, n: int = 90) -> str:
    p = urlsplit(url)
    s = p.path + (f"?{p.query}" if p.query else "")
    return s if len(s) <= n else "..." + s[-n:]


# --------------------------------------------------------------------------- #
# bundle banners
# --------------------------------------------------------------------------- #

def bundle_banners(js: str, url: str) -> list[dict]:
    """Versions declared in a bundle's leading license comments, e.g. /*! jQuery v3.5.1 | ... */."""
    head = js[:BANNER_WINDOW]
    out: list[dict] = []
    for m in BANNER.finditer(head):
        key = _lib_key(m["name"])
        if key == "react" and re.match(r"\s*\*?\s*react-dom", head[m.end():m.end() + 60],
                                       re.IGNORECASE):
            key = "react-dom"
        if key and is_release(m["ver"]) and not any(o["key"] == key for o in out):
            out.append({"key": key, "name": LIBS[key][0], "npm": LIBS[key][1],
                        "version": m["ver"], "banner": m.group(0).strip()[:70], "url": url})
    m = MOMENT_BANNER.search(head)
    if m and is_release(m["ver"]) and not any(o["key"] == "moment" for o in out):
        out.append({"key": "moment", "name": "Moment.js", "npm": "moment", "version": m["ver"],
                    "banner": "//! moment.js //! version : " + m["ver"], "url": url})
    return out
