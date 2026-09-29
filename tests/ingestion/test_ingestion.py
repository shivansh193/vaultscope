"""P1-T5 / P1-T6 - Stage 1 ingestion engine.

Acceptance (spec Section 9): sessions bucketed by IKE identifier with both
streams; NAT-T flagged; mid-session capture flagged incomplete; fragmented IKE
flagged.
"""

from __future__ import annotations

import _build as B

from core.ingestion import RawSession, ingest

_EXCHANGE_IKE_AUTH = 35
_FLAG_INITIATOR = 0x08


def _fragment_message() -> bytes:
    """An IKE message whose payload chain contains an SKF fragment (type 53)."""
    return B._message(
        _EXCHANGE_IKE_AUTH, _FLAG_INITIATOR, 1, [(53, b"\x00\x01\x00\x02" + b"\x11" * 40)]
    )


def test_ikev2_sessions_bucketed(ikev2_pcap):
    result = ingest(ikev2_pcap)
    assert len(result.sessions) >= 1
    s = result.sessions[0]
    assert isinstance(s, RawSession)
    assert s.ike_version == "IKEv2"
    assert s.ike_packets >= 1  # the IKE stream
    assert hasattr(s, "esp_records")  # the ESP stream (possibly empty)
    assert s.session_id.count("-") == 1  # spi_i-spi_r


def test_ikev1_sessions_bucketed(ikev1_pcap):
    result = ingest(ikev1_pcap)
    assert len(result.sessions) >= 1
    assert result.sessions[0].ike_version == "IKEv1"


def test_two_sas_bucket_separately(two_ikev2_sessions_pcap):
    result = ingest(two_ikev2_sessions_pcap)
    assert len(result.sessions) == 2
    assert len({s.session_id for s in result.sessions}) == 2


def test_nat_traversal_port_4500(nat_t_pcap):
    result = ingest(nat_t_pcap)
    assert any(s.nat_traversal for s in result.sessions)


def test_mid_session_capture_flagged(esp_only_pcap):
    result = ingest(esp_only_pcap)
    # no IKE handshake -> no bucketed session, ESP lands in esp_only_records
    assert result.sessions == []
    assert result.esp_only_records
    assert result.summary()["has_esp"] is True


def test_incomplete_session_flagged(tmp_path):
    # only IKE_AUTH (message_id 1) -- the SA_INIT that establishes the SA is missing
    path = B.write_pcap(tmp_path / "mid.pcap", [B.ike_auth_request(auth_method=2)])
    result = ingest(path)
    assert len(result.sessions) == 1
    assert result.sessions[0].capture_complete is False
    assert result.sessions[0].session_id in result.summary()["incomplete_sessions"]


def test_complete_session_not_flagged(ikev2_pcap):
    result = ingest(ikev2_pcap)
    assert result.sessions[0].capture_complete is True
    assert result.summary()["incomplete_sessions"] == []


def test_fragmented_ike_flag(tmp_path):
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(_fragment_message())
    result = ingest(B.write_pcap(tmp_path / "frag.pcap", msgs))
    assert any(s.fragmented_ike for s in result.sessions)


def test_esp_attached_to_the_single_session(tmp_path):
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    path = B.write_pcap(tmp_path / "ike.pcap", msgs)
    # append ESP frames to the same file
    from scapy.layers.inet import IP
    from scapy.layers.ipsec import ESP
    from scapy.utils import rdpcap, wrpcap

    frames = list(rdpcap(path)) + [
        IP(src="192.168.10.1", dst="192.168.20.1") / ESP(spi=0x2222, seq=i, data=b"\x00" * 64)
        for i in range(6)
    ]
    wrpcap(path, frames)

    result = ingest(path)
    assert len(result.sessions) == 1
    assert result.sessions[0].esp_packets == 6
    assert result.esp_only_records == []


def test_summary_shape(ikev2_pcap):
    s = ingest(ikev2_pcap).summary()
    assert set(s) >= {
        "session_count",
        "reader",
        "ike_versions",
        "has_esp",
        "incomplete_sessions",
        "nat_traversal_sessions",
    }


def test_to_vpn_sessions_runs_stage2(ikev2_pcap):
    from core.models import VPNSession

    sessions = ingest(ikev2_pcap).to_vpn_sessions()
    assert sessions and isinstance(sessions[0], VPNSession)
    assert sessions[0].ike.encryption == "AES-256-GCM"


def test_session_frames_keep_their_evidence(ikev2_pcap):
    """Frame numbers and timestamps survive bucketing -- anomaly evidence needs them."""
    s = ingest(ikev2_pcap).sessions[0]
    assert [f.frame for f in s.ike_frames] == list(range(1, s.ike_packets + 1))
    assert all(f.time > 0 for f in s.ike_frames)


def test_esp_goes_to_the_sa_between_the_same_peers(tmp_path):
    """Two tunnels, one capture: each SA gets only its own peers' ESP."""
    from scapy.layers.inet import IP
    from scapy.layers.ipsec import ESP
    from scapy.utils import rdpcap, wrpcap

    a = B.write_pcap(tmp_path / "a.pcap", B.sa_init_for_preset("aes256gcm_ecp521_pfs"))
    other_sa = [b"\x99" * 8 + m[8:] for m in B.sa_init_for_preset("3des_sha1_modp1024")]
    b = B.write_pcap(
        tmp_path / "b.pcap",
        other_sa,
        src="10.0.0.1",
        dst="10.0.0.2",
    )
    frames = list(rdpcap(a)) + list(rdpcap(b))
    frames += [IP(src="10.0.0.1", dst="10.0.0.2") / ESP(spi=7, seq=i) for i in range(1, 4)]
    path = tmp_path / "two.pcap"
    wrpcap(str(path), frames)

    by_peer = {s.initiator_ip: s for s in ingest(path).sessions}
    assert by_peer["10.0.0.1"].esp_packets == 3
    assert by_peer["192.168.10.1"].esp_packets == 0
