"""Machine exports for SIEM ingestion (Stage 5, P3-T6).

JSON is the canonical session array from spec Section 5, each record also
carrying the runtime anomalies raised against that session. CEF is ArcSight
Common Event Format -- one event per finding, one per anomaly -- for direct
SIEM import.
"""

import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from core.models import AnomalyEvent, VPNSession

CEF_VERSION = 0
CEF_VENDOR = "VaultScope"
CEF_PRODUCT = "IPsec Analyzer"
CEF_DEVICE_VERSION = "1.0"

# CEF severity is 0-10 (spec: ArcSight CEF). Map our five-level scale onto it.
_CEF_SEVERITY: dict[str, int] = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "SAFE": 0}

# Characters that terminate or delimit a CEF header field must be escaped.
_HEADER_ESCAPES = str.maketrans({"\\": "\\\\", "|": "\\|"})


def _escape_header(value: str) -> str:
    return str(value).translate(_HEADER_ESCAPES)


def _escape_extension(value: object) -> str:
    """Extension values escape backslash and '=', and must not contain raw newlines."""
    text = str(value).replace("\\", "\\\\").replace("=", "\\=")
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def to_json(
    sessions: list[VPNSession], anomalies: Sequence[AnomalyEvent] = (), indent: int = 2
) -> str:
    """Canonical session array (Section 5 schema), plus an ``anomalies`` list per
    record. The extra key is a strict superset: every record still loads back
    into a ``VPNSession`` unchanged."""
    by_session: dict[str, list[dict]] = defaultdict(list)
    for event in anomalies:
        by_session[event.session_id].append(event.model_dump(mode="json"))
    return json.dumps(
        [
            {**s.model_dump(mode="json"), "anomalies": by_session.get(s.session_id, [])}
            for s in sessions
        ],
        indent=indent,
    )


def to_cef(sessions: list[VPNSession], anomalies: Sequence[AnomalyEvent] = ()) -> str:
    """One CEF line per finding, one per clean session, one per anomaly.

    A session with no findings still emits an event so a SIEM sees the tunnel
    was assessed rather than silently missing from the feed. Anomalies carry
    the pcap frame numbers that evidence them.
    """
    peers = {s.session_id: (s.initiator_ip, s.responder_ip) for s in sessions}
    lines: list[str] = []
    for session in sessions:
        assessment = session.security_assessment
        base = {
            "src": session.initiator_ip,
            "dst": session.responder_ip,
            "cs1Label": "sessionId",
            "cs1": session.session_id,
            "cs2Label": "ikeVersion",
            "cs2": session.ike.version,
            "cs3Label": "encryption",
            "cs3": session.ike.encryption,
            "cs4Label": "dhGroup",
            "cs4": session.ike.dh_group,
            "cn1Label": "riskScore",
            "cn1": assessment.risk_score,
            "cs5Label": "trafficType",
            "cs5": session.traffic_prediction.predicted_type,
            "rt": session.timestamp,
        }

        if not assessment.findings:
            lines.append(_cef_line("VS-CLEAN", "No security findings", _CEF_SEVERITY["SAFE"], base))
            continue

        for finding in assessment.findings:
            ext = dict(base)
            ext["cs6Label"] = "standard"
            ext["cs6"] = finding.standard
            if finding.cve:
                ext["cve"] = finding.cve
            lines.append(
                _cef_line(
                    finding.rule_id,
                    finding.description,
                    _CEF_SEVERITY[finding.severity],
                    ext,
                )
            )

    for event in anomalies:
        src, dst = peers.get(event.session_id, ("", ""))
        ext = {
            "src": src,
            "dst": dst,
            "cs1Label": "sessionId",
            "cs1": event.session_id,
            "cs6Label": "evidenceFrames",
            "cs6": ",".join(map(str, event.evidence_pkts)),
            "rt": event.timestamp,
        }
        lines.append(
            _cef_line(event.anomaly_type, event.description, _CEF_SEVERITY[event.severity], ext)
        )
    return "\n".join(lines)


def _cef_line(signature_id: str, name: str, severity: int, extension: dict) -> str:
    header = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            _escape_header(CEF_VENDOR),
            _escape_header(CEF_PRODUCT),
            _escape_header(CEF_DEVICE_VERSION),
            _escape_header(signature_id),
            _escape_header(name),
            str(severity),
        ]
    )
    ext = " ".join(
        f"{k}={_escape_extension(v)}" for k, v in extension.items() if v not in (None, "")
    )
    return f"{header}|{ext}"


def write_json(
    sessions: list[VPNSession], path: str | Path, anomalies: Sequence[AnomalyEvent] = ()
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(sessions, anomalies))
    return path


def write_cef(
    sessions: list[VPNSession], path: str | Path, anomalies: Sequence[AnomalyEvent] = ()
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_cef(sessions, anomalies))
    return path
