#!/usr/bin/env python3
"""Load OSV npm bulk corpus into ClickHouse."""

import io
import json

# Add parent to path for imports
import sys
import time
import zipfile
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.intel.severity import compute_severity
from app.schema import Advisory, AffectedRange
from app.store import insert_advisories

OSV_NPM_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"


def main():
    print("Downloading OSV npm corpus...")
    start = time.perf_counter()

    with httpx.Client(timeout=120.0) as client:
        response = client.get(OSV_NPM_URL)
        response.raise_for_status()
        data = response.content

    print(f"Downloaded {len(data) / 1024 / 1024:.1f} MB")

    print("Parsing advisories...")
    advisories = []

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue

            try:
                content = zf.read(name)
                vuln = json.loads(content)
                adv = parse_osv_advisory(vuln)
                if adv:
                    advisories.append(adv)
            except Exception as e:  # noqa: BLE001 - skip a bad file, keep loading
                print(f"Failed to parse {name}: {e}")

    print(f"Parsed {len(advisories)} npm advisories")

    # Batch insert
    print("Inserting into ClickHouse...")
    batch_size = 1000
    for i in range(0, len(advisories), batch_size):
        batch = advisories[i:i + batch_size]
        insert_advisories(batch)
        print(f"  Inserted {min(i + batch_size, len(advisories))}/{len(advisories)}")

    elapsed = time.perf_counter() - start
    print(f"Done in {elapsed:.1f}s")


def parse_osv_advisory(data: dict) -> Advisory | None:
    """Parse OSV JSON into Advisory."""
    try:
        advisory_id = data.get("id", "")
        if not advisory_id:
            return None

        # Find npm affected
        npm_pkg = None
        for aff in data.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem", "").lower() == "npm":
                npm_pkg = aff
                break

        if not npm_pkg:
            return None

        package = npm_pkg.get("package", {}).get("name", "")
        if not package:
            return None

        # Ranges
        ranges = []
        for r in npm_pkg.get("ranges", []):
            events = r.get("events", [])
            introduced = fixed = last_affected = None
            for e in events:
                if "introduced" in e:
                    introduced = e["introduced"]
                if "fixed" in e:
                    fixed = e["fixed"]
                if "last_affected" in e:
                    last_affected = e["last_affected"]

            ranges.append(AffectedRange(
                type=r.get("type", "SEMVER"),
                introduced=introduced,
                fixed=fixed,
                last_affected=last_affected,
            ))

        # Dates
        from datetime import datetime
        published = modified = withdrawn = None

        for field in ("published", "modified", "withdrawn"):
            val = data.get(field)
            if val:
                try:
                    dt = datetime.fromisoformat(val)
                    if field == "published":
                        published = dt
                    elif field == "modified":
                        modified = dt
                    else:
                        withdrawn = dt
                except (ValueError, AttributeError):
                    pass

        return Advisory(
            advisory_id=advisory_id,
            aliases=data.get("aliases", []),
            ecosystem="npm",
            package=package,
            ranges=ranges,
            versions=npm_pkg.get("versions", []),
            severity=compute_severity(data),
            cvss_vector=None,
            summary=data.get("summary", ""),
            published=published,
            modified=modified,
            withdrawn=withdrawn,
            source="osv",
            source_url=f"https://osv.dev/vulnerability/{advisory_id}",
        )
    except Exception:  # noqa: BLE001 - skip any malformed advisory, keep loading the corpus
        return None


if __name__ == "__main__":
    main()
