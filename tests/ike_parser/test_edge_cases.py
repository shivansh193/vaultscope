"""P2-T4 - IKE parser edge cases: Vendor ID fingerprint, IKE fragmentation
flag, ESP anti-replay. mid-session pfs=unknown is covered in the v1/v2 suites.

These fill the ike.* fields that Stage 4c rules R14 (fragmented IKE on Cisco)
and R15 (anti-replay off) evaluate, plus the Stage 5 remediation vendor lookup.
"""

from __future__ import annotations

import _build as B

from core.ike_parser import parse_ikev1, parse_ikev2
from core.ike_parser._vendor_ids import fingerprint_vendor

# --------------------------------------------------------------------------- #
# Vendor ID fingerprinting                                                     #
# --------------------------------------------------------------------------- #


def test_strongswan_vendor_id(tmp_path):
    path = B.write_pcap(
        tmp_path / "ss.pcap", B.sa_init_with_vids("aes256gcm_ecp521_pfs", B.VID_STRONGSWAN)
    )
    assert parse_ikev2(path).ike.vendor == "strongSwan"


def test_cisco_vendor_id(tmp_path):
    path = B.write_pcap(
        tmp_path / "cisco.pcap", B.sa_init_with_vids("aes128cbc_sha256_modp2048", B.VID_CISCO_ASA)
    )
    assert parse_ikev2(path).ike.vendor == "Cisco"


def test_unknown_vendor_id_leaves_default(tmp_path):
    path = B.write_pcap(
        tmp_path / "unk.pcap", B.sa_init_with_vids("aes256gcm_ecp521_pfs", B.VID_UNKNOWN)
    )
    assert parse_ikev2(path).ike.vendor == "unknown"


def test_first_recognised_vid_wins(tmp_path):
    path = B.write_pcap(
        tmp_path / "multi.pcap",
        B.sa_init_with_vids("aes256gcm_ecp521_pfs", B.VID_UNKNOWN, B.VID_CISCO_ASA),
    )
    assert parse_ikev2(path).ike.vendor == "Cisco"


def test_fingerprint_helper_matches_ascii_string_vids():
    assert fingerprint_vendor([b"i am running strongSwan 5.9".hex()]) == "strongSwan"
    assert fingerprint_vendor([b"CISCO-DELETE-REASON".hex()]) == "Cisco"
    assert fingerprint_vendor(["00112233"]) == "unknown"


def test_ikev1_vendor_id_fingerprinted(tmp_path):
    sa = B.v1_phase1_sa()
    mm1 = B._v1_message(
        B.EXCHANGE_V1_IDENTITY_PROTECT,
        0,
        [(B.V1_PAYLOAD_SA, sa), (B.V1_PAYLOAD_VENDOR_ID, B.VID_STRONGSWAN)],
        rcookie=b"\x00" * 8,
    )
    mm2 = B._v1_message(B.EXCHANGE_V1_IDENTITY_PROTECT, 0, [(B.V1_PAYLOAD_SA, sa)])
    path = B.write_pcap(tmp_path / "v1_vid.pcap", [mm1, mm2])
    assert parse_ikev1(path).ike.vendor == "strongSwan"


# --------------------------------------------------------------------------- #
# IKE fragmentation flag                                                       #
# --------------------------------------------------------------------------- #


def test_fragmented_ike_flag_set_on_skf_payload(tmp_path):
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(B.ikev2_fragment_message())
    path = B.write_pcap(tmp_path / "frag.pcap", msgs)
    assert parse_ikev2(path).ike.fragmented_ike is True


def test_no_fragmentation_leaves_flag_false(tmp_path):
    path = B.write_pcap(tmp_path / "nofrag.pcap", B.sa_init_for_preset("aes256gcm_ecp521_pfs"))
    assert parse_ikev2(path).ike.fragmented_ike is False


def test_r14_fires_for_fragmented_cisco(tmp_path):
    from core.rules.engine import evaluate_rules

    msgs = B.sa_init_with_vids("aes128cbc_sha256_modp2048", B.VID_CISCO_ASA)
    msgs.append(B.ikev2_fragment_message())
    session = parse_ikev2(B.write_pcap(tmp_path / "r14.pcap", msgs))
    assert session.ike.fragmented_ike is True and session.ike.vendor == "Cisco"
    assert "R14" in evaluate_rules(session).triggered_rules


# --------------------------------------------------------------------------- #
# ESP anti-replay                                                              #
# --------------------------------------------------------------------------- #


def test_anti_replay_disabled_when_esp_seq_never_advances(tmp_path):
    # SA_INIT + ESP data whose sequence number is pinned at 0
    ike = B.write_pcap(tmp_path / "_ike.pcap", B.sa_init_for_preset("aes256gcm_ecp521_pfs"))
    _ = ike  # (written for parity; the ESP pcap below carries the whole session)
    esp = B.write_esp_pcap(tmp_path / "esp_static.pcap", n=10, static_seq=True)
    # merge is overkill for the test: parse the ESP-only capture, mid-session
    session = parse_ikev2(esp)
    assert session.ike.anti_replay is False


def test_anti_replay_stays_true_when_seq_advances(tmp_path):
    esp = B.write_esp_pcap(tmp_path / "esp_ok.pcap", n=10, static_seq=False)
    assert parse_ikev2(esp).ike.anti_replay is True


def test_anti_replay_undecidable_leaves_safe_default(tmp_path):
    path = B.write_pcap(tmp_path / "ike_only.pcap", B.sa_init_for_preset("aes256gcm_ecp521_pfs"))
    assert parse_ikev2(path).ike.anti_replay is True  # no ESP seen -> safe default


def test_r15_fires_when_anti_replay_off(tmp_path):
    from core.rules.engine import evaluate_rules

    session = parse_ikev2(B.write_esp_pcap(tmp_path / "r15.pcap", n=12, static_seq=True))
    assert session.ike.anti_replay is False
    assert "R15" in evaluate_rules(session).triggered_rules
