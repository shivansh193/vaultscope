"""P2-T2 - IKEv1 Main Mode + Aggressive Mode detection.

Mandatory tests from spec Section 9 ("P2-T2: IKEv1 + Aggressive Mode") plus
phase-1 crypto-parameter extraction. Fills the ``ike`` block of the canonical
``core.models.VPNSession``, so assertions read ``session.ike.<field>``.
"""

from __future__ import annotations

import _build as B
import pytest

from core.ike_parser import (
    NoIKEv1Error,
    exchange_mode_name,
    parse_ikev1,
    parse_ikev1_sessions,
)

# --------------------------------------------------------------------------- #
# spec P2-T2 mandatory tests                                                   #
# --------------------------------------------------------------------------- #


def test_aggressive_mode_detected_by_id_payload_in_message_1(aggr_pcap):
    session = parse_ikev1(aggr_pcap)
    assert session.ike.aggressive_mode is True
    # ID payload present in the first IKE message -- not inferred from count


def test_main_mode_no_aggressive_flag(main_mode_pcap):
    assert parse_ikev1(main_mode_pcap).ike.aggressive_mode is False


def test_ikev1_retransmission_does_not_flip_mode(retransmit_pcap):
    # retransmission changes message count -- must not affect mode detection
    assert parse_ikev1(retransmit_pcap).ike.aggressive_mode is False


# --------------------------------------------------------------------------- #
# phase-1 crypto parameters                                                    #
# --------------------------------------------------------------------------- #


def test_ikev1_version_and_session_id(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    assert session.ike.version == "IKEv1"
    icookie, rcookie = session.session_id.split("-")
    assert icookie == "1111111122222222"
    assert rcookie == "3333333344444444"


def test_main_mode_phase1_transform_extracted(main_mode_pcap):
    ike = parse_ikev1(main_mode_pcap).ike
    # default v1_phase1_sa(): 3DES-CBC / MD5 / PSK / MODP1024 / 28800s
    assert ike.encryption == "3DES-CBC"
    assert ike.integrity == "HMAC-MD5"
    assert ike.prf == "PRF_HMAC_MD5"
    assert ike.auth_method == "PSK"
    assert ike.dh_group == "MODP1024"
    assert ike.sa_lifetime_sec == 28800


def test_aggressive_mode_weak_suite_extracted(aggr_pcap):
    ike = parse_ikev1(aggr_pcap).ike
    # v1_aggressive_mode(): DES-CBC / MD5 / PSK / MODP1024
    assert ike.encryption == "DES-CBC"
    assert ike.dh_group == "MODP1024"
    assert ike.auth_method == "PSK"
    assert ike.aggressive_mode is True


def test_aes_keylength_attribute_applied(tmp_path):
    sa = B.v1_phase1_sa(
        enc=7, keylen=256, hash_=2, auth=3, group=14
    )  # AES-256 / SHA1 / RSA / MODP2048
    path = B.write_pcap(tmp_path / "v1_aes.pcap", B.v1_main_mode(sa=sa))
    ike = parse_ikev1(path).ike
    assert ike.encryption == "AES-256-CBC"
    assert ike.integrity == "HMAC-SHA1"
    assert ike.auth_method == "RSA"
    assert ike.dh_group == "MODP2048"


def test_xauth_auth_method(tmp_path):
    sa = B.v1_phase1_sa(auth=65001)  # XAUTHInitPreShared
    path = B.write_pcap(tmp_path / "v1_xauth.pcap", B.v1_main_mode(sa=sa))
    assert parse_ikev1(path).ike.auth_method == "XAUTH"


def test_dss_auth_method_validates_against_widened_model(tmp_path):
    sa = B.v1_phase1_sa(auth=2)  # DSS signature -- outside the spec's 4-value enum
    path = B.write_pcap(tmp_path / "v1_dss.pcap", B.v1_main_mode(sa=sa))
    assert parse_ikev1(path).ike.auth_method == "DSS"


# --------------------------------------------------------------------------- #
# record shape / helpers                                                       #
# --------------------------------------------------------------------------- #


def test_capture_complete_and_metadata(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    assert session.ike.capture_complete is True
    assert session.ike.ip_version == "IPv4"
    assert session.initiator_ip == "192.168.10.1"
    assert session.responder_ip == "192.168.20.1"
    assert session.ike.mode == "tunnel"  # phase-1 only; tunnel/transport is Quick Mode (P2-T3)


def test_exchange_mode_name_helper(main_mode_pcap, aggr_pcap):
    assert exchange_mode_name(parse_ikev1(main_mode_pcap)) == "Main Mode"
    assert exchange_mode_name(parse_ikev1(aggr_pcap)) == "Aggressive Mode"


def test_parse_from_raw_bytes():
    session = parse_ikev1(B.v1_aggressive_mode())
    assert session.ike.version == "IKEv1"
    assert session.ike.aggressive_mode is True


def test_no_ikev1_raises():
    with pytest.raises(NoIKEv1Error):
        parse_ikev1([])


def test_ikev2_capture_yields_no_ikev1_session(fixture_pcap):
    assert parse_ikev1_sessions(fixture_pcap("aes256gcm_ecp521_pfs")) == []


def test_mode_detection_survives_capture_starting_after_message_1():
    # only Main Mode messages 3-4 (KE) captured: no SA payload, exchange-type
    # byte still says Main -> not aggressive, capture flagged incomplete
    ke_only = B._v1_message(B.EXCHANGE_V1_IDENTITY_PROTECT, 0, [(B.V1_PAYLOAD_KE, B._v1_ke())])
    session = parse_ikev1([ke_only])
    assert session.ike.aggressive_mode is False
    assert session.ike.capture_complete is False


# --------------------------------------------------------------------------- #
# P2-T3 - Quick Mode: phase-2 cipher + PFS                                     #
# --------------------------------------------------------------------------- #


def test_phase1_only_capture_pfs_unknown(main_mode_pcap):
    # no Quick Mode observed -> PFS is undecidable, never guessed (spec Section 12)
    assert parse_ikev1(main_mode_pcap).ike.pfs_status == "unknown"


def test_quick_mode_phase2_cipher_extracted(tmp_path):
    p2 = B.v1_phase2_sa(esp_id=12, keylen=256, auth_alg=5)  # AES-256 / HMAC-SHA256
    path = B.write_pcap(tmp_path / "v1_qm.pcap", B.v1_main_then_quick(p2_sa=p2))
    ike = parse_ikev1(path).ike
    assert ike.encryption == "AES-256-CBC"
    assert ike.integrity == "HMAC-SHA256"


def test_quick_mode_pfs_enabled_from_ke_payload(tmp_path):
    path = B.write_pcap(tmp_path / "v1_qm_pfs.pcap", B.v1_main_then_quick(with_ke=True))
    assert parse_ikev1(path).ike.pfs_status == "enabled"


def test_quick_mode_pfs_enabled_from_group_attr(tmp_path):
    p2 = B.v1_phase2_sa(group=14)  # PFS group in the accepted proposal, no KE payload
    path = B.write_pcap(tmp_path / "v1_qm_grp.pcap", B.v1_main_then_quick(p2_sa=p2))
    ike = parse_ikev1(path).ike
    assert ike.pfs_status == "enabled"
    assert ike.dh_group == "MODP2048"


def test_quick_mode_pfs_disabled_without_ke_or_group(tmp_path):
    path = B.write_pcap(tmp_path / "v1_qm_nopfs.pcap", B.v1_main_then_quick())
    assert parse_ikev1(path).ike.pfs_status == "disabled"


def test_quick_mode_transport_encap_mode(tmp_path):
    p2 = B.v1_phase2_sa(encap=2)  # transport
    path = B.write_pcap(tmp_path / "v1_qm_transport.pcap", B.v1_main_then_quick(p2_sa=p2))
    assert parse_ikev1(path).ike.mode == "transport"


def test_quick_mode_tunnel_encap_mode(tmp_path):
    p2 = B.v1_phase2_sa(encap=1)  # tunnel
    path = B.write_pcap(tmp_path / "v1_qm_tunnel.pcap", B.v1_main_then_quick(p2_sa=p2))
    assert parse_ikev1(path).ike.mode == "tunnel"


def test_quick_mode_overrides_phase1_cipher(tmp_path):
    # phase 1 negotiates 3DES; Quick Mode negotiates AES-128 for the IPsec SA.
    # ike.encryption should reflect the IPsec SA (what protects data).
    p1 = B.v1_phase1_sa(enc=5)  # 3DES-CBC
    p2 = B.v1_phase2_sa(esp_id=12, keylen=128)  # AES-128-CBC
    path = B.write_pcap(tmp_path / "v1_qm_override.pcap", B.v1_main_then_quick(p1_sa=p1, p2_sa=p2))
    ike = parse_ikev1(path).ike
    assert ike.encryption == "AES-128-CBC"
    assert ike.prf == "PRF_HMAC_MD5"  # phase-1 concept, unchanged


def test_quick_mode_weak_des_still_flagged_via_ike_encryption(tmp_path):
    # a Quick Mode negotiating plain DES must surface as ike.encryption "DES-CBC"
    # so rule R01 fires
    p2 = B.v1_phase2_sa(esp_id=2, keylen=None)  # ESP_DES
    path = B.write_pcap(tmp_path / "v1_qm_des.pcap", B.v1_main_then_quick(p2_sa=p2))
    assert parse_ikev1(path).ike.encryption == "DES-CBC"


def test_quick_mode_body_recovered_despite_encryption_flag():
    # QM messages carry the ISAKMP ENCRYPTION flag; _wire best-effort frames the
    # (fixture / decrypted) plaintext body
    qm = B.v1_quick_mode(with_ke=True)[0]
    session = parse_ikev1([qm])
    assert session.ike.pfs_status == "enabled"  # KE payload was read


def test_quick_mode_lifetime_from_phase2(tmp_path):
    p2 = B.v1_phase2_sa(life_sec=90000)  # > 24h
    path = B.write_pcap(tmp_path / "v1_qm_life.pcap", B.v1_main_then_quick(p2_sa=p2))
    assert parse_ikev1(path).ike.sa_lifetime_sec == 90000
