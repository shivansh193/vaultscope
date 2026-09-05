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


# --- extended detectors: downgrade, NAT-T unexpected, rekey storm, evidence ---

import datetime as _dt  # noqa: E402


def _sess2(sid, src="10.0.0.1", dst="10.0.0.2", *, refs=None, ts="", **ike) -> VPNSession:
    return VPNSession(
        session_id=sid,
        initiator_ip=src,
        responder_ip=dst,
        ike=IkeParams(**ike),
        packet_refs=refs or [],
        timestamp=ts,
    )


def test_downgrade_suspected_when_pair_has_strong_and_weak():
    sessions = [
        _sess2("strong", encryption="AES-256-GCM", dh_group="ECP521"),
        _sess2("weak", encryption="DES-CBC", dh_group="MODP1024"),
    ]
    ev = [e for e in detect_anomalies(sessions) if e.anomaly_type == "DOWNGRADE_SUSPECTED"]
    assert [e.session_id for e in ev] == ["weak"]
    assert ev[0].severity == "HIGH"


def test_no_downgrade_when_all_strong():
    sessions = [
        _sess2("a", encryption="AES-256-GCM", dh_group="ECP521"),
        _sess2("b", encryption="AES-128-GCM", dh_group="ECP256"),
    ]
    assert "DOWNGRADE_SUSPECTED" not in _types(detect_anomalies(sessions))


def test_nat_t_unexpected_for_public_initiator():
    s = _sess2("pub", src="8.8.8.8", dst="1.1.1.1", nat_traversal=True)
    ev = [e for e in detect_anomalies([s]) if e.anomaly_type == "NAT_T_UNEXPECTED"]
    assert ev and ev[0].severity == "MEDIUM"


def test_nat_t_ok_for_private_initiator():
    s = _sess2("priv", src="10.0.0.5", dst="8.8.8.8", nat_traversal=True)
    assert "NAT_T_UNEXPECTED" not in _types(detect_anomalies([s]))


def test_rekey_storm_flagged_within_window():
    base = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.UTC)
    sessions = [
        _sess2(f"r{i}", ts=(base + _dt.timedelta(seconds=i * 10)).isoformat()) for i in range(5)
    ]
    ev = [e for e in detect_anomalies(sessions) if e.anomaly_type == "REKEY_STORM"]
    assert len(ev) == 5


def test_rekey_spread_over_hours_is_not_a_storm():
    base = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.UTC)
    sessions = [_sess2(f"r{i}", ts=(base + _dt.timedelta(hours=i)).isoformat()) for i in range(5)]
    assert "REKEY_STORM" not in _types(detect_anomalies(sessions))


def test_evidence_pkts_carried_from_session():
    s = _sess2("s1", refs=[47, 48, 49], version="IKEv1", aggressive_mode=True)
    ev = [e for e in detect_anomalies([s]) if e.anomaly_type == "AGGRESSIVE_MODE_PROBE"]
    assert ev[0].evidence_pkts == [47, 48, 49]
