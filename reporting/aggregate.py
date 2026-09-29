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


# Set by the pipeline on a session whose peers carried no ESP: nothing was
# classified, so it belongs in no traffic statistic.
NO_ESP = "no-esp-observed"


def classified(sessions: list[VPNSession]) -> list[VPNSession]:
    """Sessions that actually had a traffic prediction made."""
    return [s for s in sessions if s.traffic_prediction.model_version != NO_ESP]


def traffic_mix(sessions: list[VPNSession]) -> dict[str, int]:
    return dict(Counter(s.traffic_prediction.predicted_type for s in classified(sessions)))


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


def metadata_exposure(sessions: list[VPNSession]) -> dict[str, Any]:
    """Fleet exposure: mean score, level mix, and how many sessions leak each signal."""
    if not sessions:
        return {"mean_score": 0, "levels": {}, "signals": {}}
    exposures = [s.security_assessment.metadata_exposure for s in sessions]
    signals = Counter(
        sig.signal for e in exposures for sig in e.signals if sig.level in ("High", "Med")
    )
    return {
        "mean_score": round(sum(e.score for e in exposures) / len(exposures)),
        "levels": dict(Counter(e.level for e in exposures)),
        "signals": dict(signals.most_common()),
    }


def compliance(sessions: list[VPNSession]) -> list[dict[str, Any]]:
    """Per baseline: how many sessions pass, fail or could not be assessed."""
    rows: dict[str, dict[str, Any]] = {}
    for session in sessions:
        for c in session.security_assessment.compliance:
            row = rows.setdefault(
                c.baseline_id,
                {
                    "baseline_id": c.baseline_id,
                    "name": c.name,
                    "pass": 0,
                    "fail": 0,
                    "not_assessed": 0,
                    "violations": Counter(),
                },
            )
            row[c.status] += 1
            row["violations"].update(c.violations)
    for row in rows.values():
        row["violations"] = [v for v, _ in row["violations"].most_common(5)]
    return list(rows.values())


def pqc_readiness(sessions: list[VPNSession]) -> dict[str, int]:
    return dict(Counter(s.ike.pqc_status for s in sessions))


def summarise(sessions: list[VPNSession]) -> dict[str, Any]:
    """Everything a report template needs, in one dict."""
    return {
        "session_count": len(sessions),
        "posture_score": posture_score(sessions),
        "severity_counts": severity_counts(sessions),
        "top_findings": top_findings(sessions),
        "traffic_mix": traffic_mix(sessions),
        "threat_matrix": threat_matrix(sessions),
        "classified_count": len(classified(sessions)),
        "metadata_exposure": metadata_exposure(sessions),
        "compliance": compliance(sessions),
        "pqc_readiness": pqc_readiness(sessions),
        "abstained_count": sum(1 for s in classified(sessions) if s.traffic_prediction.abstained),
        "mean_ai_confidence": (
            round(
                sum(s.traffic_prediction.confidence for s in classified(sessions))
                / len(classified(sessions)),
                3,
            )
            if classified(sessions)
            else None
        ),
    }
