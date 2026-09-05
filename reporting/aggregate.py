"""Fleet-level rollups over a set of analysed sessions (Stage 5).

Report templates and the dashboard's aggregate view both need the same
summary numbers, so they are computed here once rather than in each template.
"""

from collections import Counter
from typing import Any

from core.models import SEVERITY_ORDER, Finding, VPNSession

# CVE / standard reference links for the technical report.
_STANDARD_LINKS: dict[str, str] = {
    "RFC 8247": "https://www.rfc-editor.org/rfc/rfc8247",
    "RFC 9395": "https://www.rfc-editor.org/rfc/rfc9395",
    "RFC 4303": "https://www.rfc-editor.org/rfc/rfc4303",
    "NIST SP 800-77": "https://csrc.nist.gov/pubs/sp/800/77/r1/final",
    "CNSSP-15": "https://www.cnss.gov/CNSS/issuances/Policies.cfm",
}


def cve_url(cve: str | None) -> str | None:
    return f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None


def standard_url(standard: str) -> str | None:
    for key, url in _STANDARD_LINKS.items():
        if key in (standard or ""):
            return url
    return None


def posture_score(sessions: list[VPNSession]) -> int:
    """Fleet posture = mean session risk score, rounded. 100 when empty."""
    if not sessions:
        return 100
    return round(sum(s.security_assessment.risk_score for s in sessions) / len(sessions))


def severity_counts(sessions: list[VPNSession]) -> dict[str, int]:
    counts = Counter(s.security_assessment.overall_severity for s in sessions)
    return {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER}


def top_findings(sessions: list[VPNSession], limit: int = 3) -> list[dict[str, Any]]:
    """Most severe findings first, deduplicated by rule and counted by session.

    The executive report shows the three issues worth acting on, not three
    copies of the same issue seen on different peers.
    """
    by_rule: dict[str, dict[str, Any]] = {}
    for session in sessions:
        for finding in session.security_assessment.findings:
            entry = by_rule.setdefault(
                finding.rule_id,
                {"finding": finding, "session_count": 0, "sessions": []},
            )
            entry["session_count"] += 1
            entry["sessions"].append(session.session_id)

    ranked = sorted(
        by_rule.values(),
        key=lambda e: (SEVERITY_ORDER.index(e["finding"].severity), -e["session_count"]),
    )
    return ranked[:limit]


def traffic_mix(sessions: list[VPNSession]) -> dict[str, int]:
    return dict(Counter(s.traffic_prediction.predicted_type for s in sessions))


def threat_matrix(sessions: list[VPNSession]) -> list[dict[str, Any]]:
    """Deduplicated threat entries across the fleet, worst first."""
    seen: dict[str, dict[str, Any]] = {}
    for session in sessions:
        for entry in session.security_assessment.threat_matrix:
            seen.setdefault(
                entry.threat,
                {"threat": entry.threat, "likelihood": entry.likelihood, "impact": entry.impact},
            )
    order = {"High": 0, "Med": 1, "Low": 2}
    return sorted(seen.values(), key=lambda e: (order[e["impact"]], order[e["likelihood"]]))


def all_findings(sessions: list[VPNSession]) -> list[tuple[str, Finding]]:
    return [(s.session_id, f) for s in sessions for f in s.security_assessment.findings]


def summarise(sessions: list[VPNSession]) -> dict[str, Any]:
    """Everything a report template needs, in one dict."""
    return {
        "session_count": len(sessions),
        "posture_score": posture_score(sessions),
        "severity_counts": severity_counts(sessions),
        "top_findings": top_findings(sessions),
        "traffic_mix": traffic_mix(sessions),
        "threat_matrix": threat_matrix(sessions),
        "mean_ai_confidence": (
            round(sum(s.traffic_prediction.confidence for s in sessions) / len(sessions), 3)
            if sessions
            else 0.0
        ),
    }
