"""Curated map from a fingerprinted product name to its NVD CPE vendor and product.

Only well-known server software, CMSs and languages are listed. A name not in the table is
skipped, never guessed: a wrong CPE would attach someone else's CVEs to the site. JS libraries are
left out on purpose because they are matched against OSV by their npm name.
"""

# Lowercased Tech.name -> (CPE vendor, CPE product).
CPE_TABLE: dict[str, tuple[str, str]] = {
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "openresty": ("openresty", "openresty"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "jetty": ("eclipse", "jetty"),
    "tomcat": ("apache", "tomcat"),
    "php": ("php", "php"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla!": ("joomla", "joomla\\!"),
    "joomla": ("joomla", "joomla\\!"),
}


def cpe_for(name: str | None) -> tuple[str, str] | None:
    """(vendor, product) for a fingerprinted name, or None when it is not in the table."""
    return CPE_TABLE.get((name or "").strip().lower())


def virtual_match_string(vendor: str, product: str, version: str) -> str:
    """CPE 2.3 name for NVD's virtualMatchString: a version-specific application CPE."""
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
