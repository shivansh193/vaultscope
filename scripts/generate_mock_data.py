"""Regenerate the mock data contract fixtures (spec Section 11).

    python scripts/generate_mock_data.py

Writes data/mock/{sessions.json, session_001.json, ws_stream.json}. These back
two things: the frontend's development mode before the backend is running, and
core.pipeline's FIXTURE MODE while Block A's IKE parser is unbuilt.

Sessions are deliberately spread across severities and vendors so the dashboard
exercises every colour, badge and empty state.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.models import FlowFeatures, IkeParams, TrafficPrediction, VPNSession  # noqa: E402
from core.rules.engine import evaluate_rules  # noqa: E402

OUT_DIR = REPO_ROOT / "data" / "mock"

# (id, initiator, responder, traffic, confidence, ike overrides)
SPECS = [
    (
        "sess-001",
        "10.10.1.5",
        "203.0.113.9",
        "VoIP",
        0.91,
        dict(
            version="IKEv1",
            aggressive_mode=True,
            auth_method="PSK",
            encryption="3DES-CBC",
            integrity="HMAC-SHA1",
            dh_group="MODP1024",
            pfs_status="disabled",
            sa_lifetime_sec=90000,
            vendor="Cisco ASA 9.8",
        ),
    ),
    (
        "sess-002",
        "10.10.1.6",
        "203.0.113.9",
        "Video",
        0.87,
        dict(
            encryption="DES-CBC",
            integrity="HMAC-MD5",
            dh_group="MODP768",
            pfs_status="disabled",
            auth_method="PSK",
            vendor="Juniper SRX 21.4",
        ),
    ),
    (
        "sess-003",
        "10.10.2.11",
        "198.51.100.4",
        "Web",
        0.78,
        dict(
            dh_group="MODP1536",
            pfs_status="disabled",
            sa_lifetime_sec=43200,
            vendor="Fortinet FortiGate 7.2",
        ),
    ),
    (
        "sess-004",
        "10.10.2.12",
        "198.51.100.4",
        "Email",
        0.66,
        dict(
            version="IKEv1", auth_method="RSA", integrity="HMAC-SHA1", vendor="Palo Alto PAN-OS 11"
        ),
    ),
    (
        "sess-005",
        "10.10.3.20",
        "192.0.2.50",
        "Chat",
        0.59,
        dict(pfs_status="disabled", sa_lifetime_sec=36000, vendor="strongSwan 5.9"),
    ),
    (
        "sess-006",
        "10.10.3.21",
        "192.0.2.50",
        "ICMP",
        0.95,
        dict(sa_lifetime_sec=30000, vendor="strongSwan 5.9"),
    ),
    (
        "sess-007",
        "10.10.4.30",
        "203.0.113.77",
        "Web",
        0.83,
        dict(anti_replay=False, vendor="Cisco ASA 9.12"),
    ),
    (
        "sess-008",
        "10.10.4.31",
        "203.0.113.77",
        "Video",
        0.72,
        dict(fragmented_ike=True, vendor="Cisco ASA 9.12"),
    ),
    (
        "sess-009",
        "10.10.5.40",
        "198.51.100.200",
        "VoIP",
        0.88,
        dict(vendor="strongSwan 5.9", ip_version="IPv6"),
    ),
    (
        "sess-010",
        "10.10.5.41",
        "198.51.100.200",
        "Web",
        0.93,
        dict(vendor="Fortinet FortiGate 7.4", mode="transport"),
    ),
]

FLOW_BY_TYPE = {
    "VoIP": dict(
        pkt_size_mean=172.0,
        pkt_size_std=11.0,
        iat_mean_ms=20.0,
        iat_std_ms=3.0,
        dir_ratio=1.02,
        burst_count=2,
        flow_duration_sec=182.0,
        pkt_total=9100,
        rate_pps=50.0,
    ),
    "Video": dict(
        pkt_size_mean=1284.0,
        pkt_size_std=290.0,
        iat_mean_ms=7.5,
        iat_std_ms=9.0,
        dir_ratio=0.04,
        burst_count=64,
        flow_duration_sec=240.0,
        pkt_total=31000,
        rate_pps=129.0,
    ),
    "Web": dict(
        pkt_size_mean=712.0,
        pkt_size_std=520.0,
        iat_mean_ms=140.0,
        iat_std_ms=310.0,
        dir_ratio=0.18,
        burst_count=23,
        flow_duration_sec=95.0,
        pkt_total=1450,
        rate_pps=15.3,
    ),
    "Email": dict(
        pkt_size_mean=940.0,
        pkt_size_std=410.0,
        iat_mean_ms=260.0,
        iat_std_ms=520.0,
        dir_ratio=2.4,
        burst_count=8,
        flow_duration_sec=44.0,
        pkt_total=380,
        rate_pps=8.6,
    ),
    "Chat": dict(
        pkt_size_mean=138.0,
        pkt_size_std=64.0,
        iat_mean_ms=2100.0,
        iat_std_ms=3400.0,
        dir_ratio=1.1,
        burst_count=31,
        flow_duration_sec=610.0,
        pkt_total=290,
        rate_pps=0.48,
    ),
    "ICMP": dict(
        pkt_size_mean=98.0,
        pkt_size_std=0.5,
        iat_mean_ms=1000.0,
        iat_std_ms=2.0,
        dir_ratio=1.0,
        burst_count=1,
        flow_duration_sec=60.0,
        pkt_total=60,
        rate_pps=1.0,
    ),
}


def build() -> list[VPNSession]:
    sessions = []
    for index, (sid, src, dst, traffic, confidence, ike) in enumerate(SPECS):
        session = VPNSession(
            session_id=sid,
            capture_source="pcap_upload",
            capture_file="lab_capture.pcap",
            timestamp=f"2026-09-05T10:{index:02d}:00Z",
            initiator_ip=src,
            responder_ip=dst,
            ike=IkeParams(**ike),
            flow_features=FlowFeatures(**FLOW_BY_TYPE[traffic]),
            traffic_prediction=TrafficPrediction(
                predicted_type=traffic, confidence=confidence, model_version="rf-v1-mock"
            ),
        )
        session.security_assessment = evaluate_rules(session)
        session.security_assessment.ai_confidence = confidence
        sessions.append(session)
    return sessions


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sessions = build()

    (OUT_DIR / "sessions.json").write_text(
        json.dumps([s.model_dump(mode="json") for s in sessions], indent=2) + "\n"
    )
    (OUT_DIR / "session_001.json").write_text(
        json.dumps(sessions[0].model_dump(mode="json"), indent=2) + "\n"
    )
    # One event per line-delay, as the WS contract describes (1 per second).
    (OUT_DIR / "ws_stream.json").write_text(
        json.dumps(
            [
                {"delay_ms": 1000 * i, "event": "session", "data": s.model_dump(mode="json")}
                for i, s in enumerate(sessions)
            ],
            indent=2,
        )
        + "\n"
    )

    counts: dict[str, int] = {}
    for s in sessions:
        sev = s.security_assessment.overall_severity
        counts[sev] = counts.get(sev, 0) + 1
    print(f"wrote {len(sessions)} sessions to {OUT_DIR}")
    print("severity mix:", counts)


if __name__ == "__main__":
    main()
