"""Severity computation from advisory data."""

from cvss import CVSS3
from cvss.exceptions import CVSSError


def compute_severity(data: dict) -> str:
    """Compute severity from OSV data."""
    # Check GHSA database_specific.severity
    db_specific = data.get("database_specific", {})
    ghsa_severity = db_specific.get("severity")
    if ghsa_severity:
        s = ghsa_severity.lower()
        if s == "moderate":
            return "medium"
        if s in ("critical", "high", "medium", "low"):
            return s

    # Check CVSS vector
    for sev in data.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            vector = sev.get("score")
            if vector:
                try:
                    cvss = CVSS3(vector)
                    score = cvss.base_score
                    if score >= 9.0:
                        return "critical"
                    elif score >= 7.0:
                        return "high"
                    elif score >= 4.0:
                        return "medium"
                    else:
                        return "low"
                except CVSSError:
                    pass

    return "unknown"
