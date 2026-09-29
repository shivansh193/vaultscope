"""The Analysis module: capture in, assessed Analysis out.

Every test drives ``analyze_capture`` with a real pcap written by the Stage 2
synthetic builders -- the interface is the test surface, so nothing here
reaches past it into a stage.
"""

import sys
from pathlib import Path

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap

from core import pipeline
from core.models import VPNSession

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ike_parser"))
import _build as B  # noqa: E402


def _esp(src, dst, n=40, spi=0x1234, size=160, gap=0.02, t0=1_700_000_100.0):
    frames = []
    for i in range(n):
        pkt = IP(src=src, dst=dst) / ESP(spi=spi, seq=i + 1, data=b"\x00" * size)
        pkt.time = t0 + i * gap
        frames.append(pkt)
    return frames


def _stamp(frames, t0=1_700_000_000.0):
    for i, f in enumerate(frames):
        f.time = t0 + i * 0.01
    return frames


def _sa(tmp_path, preset, *, spi=None, src="192.168.10.1", dst="192.168.20.1", name="sa"):
    msgs = B.sa_init_for_preset(preset)
    if spi is not None:
        msgs = [spi + m[8:] for m in msgs]
    return list(rdpcap(B.write_pcap(tmp_path / f"{name}.pcap", msgs, src=src, dst=dst)))


def _write(tmp_path, frames, name="capture.pcap") -> Path:
    path = tmp_path / name
    wrpcap(str(path), frames)
    return path


@pytest.fixture
def two_tunnels(tmp_path) -> Path:
    """A strong tunnel with ESP and a weak one without, in one capture."""
    frames = _stamp(
        _sa(tmp_path, "aes256gcm_ecp521_pfs", name="a")
        + _sa(tmp_path, "3des_sha1_modp1024", spi=b"\x99" * 8, src="10.0.0.1", dst="10.0.0.2")
    )
    return _write(tmp_path, frames + _esp("192.168.10.1", "192.168.20.1"))


def test_every_sa_is_its_own_session(two_tunnels):
    analysis = pipeline.analyze_capture(two_tunnels)
    by_peer = {s.initiator_ip: s for s in analysis.sessions}
    assert set(by_peer) == {"192.168.10.1", "10.0.0.1"}
    assert by_peer["192.168.10.1"].ike.encryption == "AES-256-GCM"
    assert by_peer["10.0.0.1"].ike.encryption == "3DES-CBC"


def test_sessions_carry_evidence_frames_and_timestamps(two_tunnels):
    """Evidence must point at real frames in the file, per SA."""
    by_peer = {s.initiator_ip: s for s in pipeline.analyze_capture(two_tunnels).sessions}
    assert by_peer["192.168.10.1"].packet_refs == [1, 2]
    assert by_peer["10.0.0.1"].packet_refs == [3, 4]
    assert by_peer["192.168.10.1"].timestamp.startswith("2023-11-14T22:13:20")


def test_traffic_is_inferred_only_where_esp_was_seen(two_tunnels):
    by_peer = {s.initiator_ip: s for s in pipeline.analyze_capture(two_tunnels).sessions}
    with_esp, without = by_peer["192.168.10.1"], by_peer["10.0.0.1"]
    assert with_esp.flow_features.pkt_total == 40
    assert with_esp.traffic_prediction.model_version != pipeline.NO_ESP_MODEL_VERSION
    assert without.flow_features.pkt_total == 0
    assert without.traffic_prediction.predicted_type == "Other"
    assert without.traffic_prediction.confidence == 0.0
    assert without.traffic_prediction.model_version == pipeline.NO_ESP_MODEL_VERSION


def test_every_session_is_assessed(two_tunnels):
    by_peer = {s.initiator_ip: s for s in pipeline.analyze_capture(two_tunnels).sessions}
    weak = by_peer["10.0.0.1"].security_assessment
    assert {"R02", "R04"} <= set(weak.triggered_rules)
    assert weak.overall_severity == "CRITICAL"
    assert weak.findings[0].remediation


def test_ipv6_and_nat_t_come_from_the_wire(tmp_path):
    msgs = B.sa_init_for_preset("aes128cbc_sha256_modp2048")
    frames = [
        IPv6(src=s, dst=d) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00" * 4 + m)
        for m, (s, d) in zip(msgs, [("fd00::1", "fd00::2"), ("fd00::2", "fd00::1")], strict=True)
    ]
    session = pipeline.analyze_capture(_write(tmp_path, _stamp(frames))).sessions[0]
    assert session.ike.ip_version == "IPv6"
    assert session.ike.nat_traversal is True
    assert session.initiator_ip == "fd00::1"


def test_capture_metadata_is_stamped(two_tunnels):
    for session in pipeline.analyze_capture(two_tunnels, source="live_nic").sessions:
        assert session.capture_file == "capture.pcap"
        assert session.capture_source == "live_nic"


def test_stats_describe_the_capture(two_tunnels):
    stats = pipeline.analyze_capture(two_tunnels).stats
    assert (stats.packets, stats.ike_packets, stats.esp_packets) == (44, 4, 40)
    assert stats.sessions == 2
    assert stats.incomplete_sessions == 0
    assert stats.duration_sec > 0


def test_anomalies_come_back_with_evidence(tmp_path):
    frames = _stamp(list(rdpcap(B.write_pcap(tmp_path / "am.pcap", B.v1_aggressive_mode()))))
    analysis = pipeline.analyze_capture(_write(tmp_path, frames))
    [event] = [e for e in analysis.anomalies if e.anomaly_type == "AGGRESSIVE_MODE_PROBE"]
    assert event.evidence_pkts == analysis.sessions[0].packet_refs
    assert event.evidence_pkts and event.timestamp


def test_mid_session_capture_guesses_nothing(tmp_path):
    """ESP with no handshake: crypto unknown, never the strong-suite defaults."""
    analysis = pipeline.analyze_capture(_write(tmp_path, _esp("10.9.0.1", "10.9.0.2")))
    [session] = analysis.sessions
    assert session.session_id == "esp-00001234"
    assert session.ike.capture_complete is False
    assert session.ike.encryption == session.ike.dh_group == "unknown"
    assert session.ike.auth_method is None
    assert session.initiator_ip == "10.9.0.1"
    assert session.traffic_prediction.model_version != pipeline.NO_ESP_MODEL_VERSION
    assert session.security_assessment.overall_severity == "SAFE"
    assert analysis.anomalies == []


def test_empty_capture_is_an_empty_analysis(tmp_path):
    path = _write(tmp_path, [IP(src="1.1.1.1", dst="2.2.2.2") / UDP(dport=53)])
    analysis = pipeline.analyze_capture(path)
    assert analysis.sessions == [] and analysis.anomalies == []
    assert analysis.stats.packets == 1


def test_one_malformed_sa_does_not_sink_the_rest(two_tunnels, monkeypatch):
    real = pipeline.parse_ikev2_sessions

    def flaky(raw):
        if raw.initiator_ip == "10.0.0.1":
            raise ValueError("malformed")
        return real(raw)

    monkeypatch.setattr(pipeline, "parse_ikev2_sessions", flaky)
    assert [s.initiator_ip for s in pipeline.analyze_capture(two_tunnels).sessions] == [
        "192.168.10.1"
    ]


# --- Stage 4a fallback ------------------------------------------------------------
def _gap_session() -> VPNSession:
    session = VPNSession(session_id="s")
    session.ike.encryption = "unknown"
    session.ike.dh_group = "ECP256"
    return session


def _raw_with_sa_init(tmp_path):
    from core.ingestion import ingest

    path = B.write_pcap(tmp_path / "x.pcap", B.sa_init_for_preset("aes256gcm_ecp521_pfs"))
    return ingest(path).sessions[0]


def test_stage_4a_fills_only_unknown_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "predict_ike_params",
        lambda msgs: {"encryption": "AES-128-CBC", "dh_group": "MODP1024", "confidence": 0.9},
    )
    session = _gap_session()
    pipeline._fill_from_structure(session, _raw_with_sa_init(tmp_path))
    assert session.ike.encryption == "AES-128-CBC"
    assert session.ike.dh_group == "ECP256"  # observed; never overwritten
    assert session.ike.confidence_source == "classifier"


def test_stage_4a_ignores_a_low_confidence_guess(tmp_path, monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "predict_ike_params",
        lambda msgs: {"encryption": "DES-CBC", "dh_group": "MODP768", "confidence": 0.3},
    )
    session = _gap_session()
    pipeline._fill_from_structure(session, _raw_with_sa_init(tmp_path))
    assert session.ike.encryption == "unknown"
    assert session.ike.confidence_source == "parser"


def test_lone_tunnel_behind_nat_keeps_its_esp_end_to_end(tmp_path):
    """ESP captured under NATed addresses belongs to the one SA in the capture:
    no phantom mid-session record, and the real session is classified."""
    frames = _stamp(_sa(tmp_path, "aes256gcm_ecp521_pfs"))
    frames += _esp("100.64.0.9", "192.168.20.1", n=29, spi=0x77)
    analysis = pipeline.analyze_capture(_write(tmp_path, frames))

    [session] = analysis.sessions
    assert session.flow_features.pkt_total == 29
    assert session.traffic_prediction.model_version != pipeline.NO_ESP_MODEL_VERSION
    assert (analysis.stats.sessions, analysis.stats.orphan_esp_packets) == (1, 0)


def test_unobserved_mode_lifetime_and_anti_replay_are_not_reported(tmp_path):
    """Neither the handshake-only nor the ESP-only session may show defaults."""
    frames = _stamp(_sa(tmp_path, "aes256gcm_ecp521_pfs"))
    frames += _esp("10.9.0.1", "10.9.0.2")  # orphan ESP -> mid-session record
    by_id = {
        s.session_id.startswith("esp-"): s
        for s in pipeline.analyze_capture(_write(tmp_path, frames)).sessions
    }
    handshake, esp_only = by_id[False], by_id[True]
    assert handshake.ike.mode == esp_only.ike.mode == "unknown"
    assert handshake.ike.sa_lifetime_sec is None and esp_only.ike.sa_lifetime_sec is None
    assert handshake.ike.anti_replay is None  # no ESP of its own
    assert esp_only.ike.anti_replay is True  # 40 advancing sequence numbers


def test_findings_on_inferred_fields_say_so(tmp_path, monkeypatch):
    """A Stage 4a guess that trips a rule is carried into the finding."""
    from core.rules.engine import evaluate_rules

    monkeypatch.setattr(
        pipeline,
        "predict_ike_params",
        lambda msgs: {"encryption": "3DES-CBC", "dh_group": "MODP1024", "confidence": 0.9},
    )
    session = _gap_session()
    pipeline._fill_from_structure(session, _raw_with_sa_init(tmp_path))
    assert session.ike.inferred_fields == ["encryption"]
    findings = {f.rule_id: f for f in evaluate_rules(session).findings}
    assert findings["R02"].inferred_from == ["encryption"]  # 3DES, guessed
