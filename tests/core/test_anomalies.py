"""Protocol anomaly detection (spec Section 9, P3-T10)."""

from core.anomalies import (
    AGGRESSIVE_PROBE_THRESHOLD,
    TRANSFORM_BRUTEFORCE_THRESHOLD,
    detect_anomalies,
)
from core.models import IkeParams, VPNSession


def _session(sid, src="10.0.0.1", dst="10.0.0.2", **ike) -> VPNSession:
    return VPNSession(session_id=sid, initiator_ip=src, responder_ip=dst, ike=IkeParams(**ike))


def _types(events) -> set[str]:
    return {e.anomaly_type for e in events}


def test_aggressive_mode_is_flagged():
    events = detect_anomalies([_session("s1", version="IKEv1", aggressive_mode=True)])
    assert "AGGRESSIVE_MODE_PROBE" in _types(events)


def test_repeated_aggressive_mode_escalates_to_critical():
    sessions = [
        _session(f"s{i}", src=f"10.0.0.{i}", version="IKEv1", aggressive_mode=True)
        for i in range(AGGRESSIVE_PROBE_THRESHOLD)
    ]
    events = [e for e in detect_anomalies(sessions) if e.anomaly_type == "AGGRESSIVE_MODE_PROBE"]
    assert events
    assert all(e.severity == "CRITICAL" for e in events)


def test_single_aggressive_mode_is_high_not_critical():
    events = [
        e
        for e in detect_anomalies([_session("s1", version="IKEv1", aggressive_mode=True)])
        if e.anomaly_type == "AGGRESSIVE_MODE_PROBE"
    ]
    assert [e.severity for e in events] == ["HIGH"]


def test_ikev2_is_never_an_aggressive_mode_probe():
    """Aggressive Mode is an IKEv1 concept; a stray flag on IKEv2 is not a probe."""
    events = detect_anomalies([_session("s1", version="IKEv2", aggressive_mode=True)])
    assert "AGGRESSIVE_MODE_PROBE" not in _types(events)


def test_transform_bruteforce_detected_on_many_proposals():
    ciphers = ["AES-256-GCM", "AES-128-CBC", "3DES-CBC", "DES-CBC", "AES-256-CBC"]
    sessions = [
        _session(f"s{i}", encryption=cipher)
        for i, cipher in enumerate(ciphers[:TRANSFORM_BRUTEFORCE_THRESHOLD])
    ]
    assert "TRANSFORM_BRUTEFORCE" in _types(detect_anomalies(sessions))


def test_few_proposals_are_not_bruteforce():
    sessions = [_session("s1", encryption="AES-256-GCM"), _session("s2", encryption="AES-128-CBC")]
    assert "TRANSFORM_BRUTEFORCE" not in _types(detect_anomalies(sessions))


def test_proposals_from_different_peers_are_not_bruteforce():
    """Enumeration is per peer pair; unrelated peers each using their own cipher
    must not aggregate into a false positive."""
    ciphers = ["AES-256-GCM", "AES-128-CBC", "3DES-CBC", "DES-CBC", "AES-256-CBC"]
    sessions = [
        _session(f"s{i}", src=f"10.0.{i}.1", dst=f"10.9.{i}.1", encryption=c)
        for i, c in enumerate(ciphers)
    ]
    assert "TRANSFORM_BRUTEFORCE" not in _types(detect_anomalies(sessions))


def test_spi_collision_detected_across_peer_pairs():
    sessions = [
        _session("same-spi", src="10.0.0.1", dst="10.0.0.2"),
        _session("same-spi", src="10.0.0.9", dst="10.0.0.8"),
    ]
    events = [e for e in detect_anomalies(sessions) if e.anomaly_type == "SPI_COLLISION"]
    assert events and events[0].severity == "CRITICAL"


def test_same_spi_same_peers_is_not_a_collision():
    sessions = [_session("same-spi"), _session("same-spi")]
    assert "SPI_COLLISION" not in _types(detect_anomalies(sessions))


def test_clean_capture_yields_no_anomalies():
    assert detect_anomalies([_session("s1"), _session("s2", src="10.0.0.3")]) == []


def test_empty_capture_yields_no_anomalies():
    assert detect_anomalies([]) == []


def test_every_event_has_a_unique_id():
    sessions = [
        _session(f"s{i}", src=f"10.0.0.{i}", version="IKEv1", aggressive_mode=True)
        for i in range(4)
    ]
    events = detect_anomalies(sessions)
    assert len({e.anomaly_id for e in events}) == len(events)
