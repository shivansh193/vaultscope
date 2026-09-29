"""The two committed demo captures say what the demo script claims they say."""

from collections import Counter
from pathlib import Path

import pytest

from core.pipeline import analyze_capture

DEMO = Path(__file__).resolve().parents[2] / "data" / "demo"


def test_attack_capture_trips_every_detector_it_was_built_for():
    analysis = analyze_capture(DEMO / "attack_capture.pcap")
    kinds = Counter(e.anomaly_type for e in analysis.anomalies)
    assert set(kinds) == {
        "AGGRESSIVE_MODE_PROBE",
        "TRANSFORM_BRUTEFORCE",
        "DOWNGRADE_SUSPECTED",
        "NAT_T_UNEXPECTED",
        "REKEY_STORM",
    }
    # Every event points at frames that exist in the file.
    assert all(
        e.evidence_pkts and max(e.evidence_pkts) <= analysis.stats.packets
        for e in analysis.anomalies
    )


@pytest.mark.slow
def test_demo_capture_is_six_tunnels_with_traffic():
    analysis = analyze_capture(DEMO / "demo_capture.pcap")
    assert analysis.stats.sessions == 6
    severities = Counter(s.security_assessment.overall_severity for s in analysis.sessions)
    assert severities == {"CRITICAL": 3, "HIGH": 1, "SAFE": 2}
    assert all(s.flow_features.pkt_total > 0 for s in analysis.sessions)
    assert all(s.timestamp and s.packet_refs for s in analysis.sessions)
