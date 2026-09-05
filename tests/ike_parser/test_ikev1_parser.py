"""P2-T2 - IKEv1 Main Mode + Aggressive Mode detection.

Mandatory tests from spec Section 9 ("P2-T2: IKEv1 + Aggressive Mode") plus
phase-1 crypto-parameter extraction and the raw-bytes entry point.
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
    assert session.aggressive_mode is True
    # ID payload present in the first IKE message -- not inferred from count


def test_main_mode_no_aggressive_flag(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    assert session.aggressive_mode is False


def test_ikev1_retransmission_does_not_flip_mode(retransmit_pcap):
    # retransmission changes message count -- must not affect mode detection
    session = parse_ikev1(retransmit_pcap)
    assert session.aggressive_mode is False  # main mode pcap with retransmit


# --------------------------------------------------------------------------- #
# phase-1 crypto parameters                                                    #
# --------------------------------------------------------------------------- #


def test_ikev1_version_and_session_id(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    assert session.ike_version == "IKEv1"
    icookie, rcookie = session.session_id.split("-")
    assert icookie == "1111111122222222"
    assert rcookie == "3333333344444444"


def test_main_mode_phase1_transform_extracted(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    # default v1_phase1_sa(): 3DES-CBC / MD5 / PSK / MODP1024 / 28800s
    assert session.encryption == "3DES-CBC"
    assert session.integrity == "HMAC-MD5"
    assert session.prf == "PRF_HMAC_MD5"
    assert session.auth_method == "PSK"
    assert session.dh_group == "MODP1024"
    assert session.sa_lifetime_sec == 28800


def test_aggressive_mode_weak_suite_extracted(aggr_pcap):
    session = parse_ikev1(aggr_pcap)
    # v1_aggressive_mode(): DES-CBC / MD5 / PSK / MODP1024
    assert session.encryption == "DES-CBC"
    assert session.dh_group == "MODP1024"
    assert session.auth_method == "PSK"
    assert session.aggressive_mode is True


def test_aes_keylength_attribute_applied(main_mode_pcap, tmp_path):
    sa = B.v1_phase1_sa(
        enc=7, keylen=256, hash_=2, auth=3, group=14
    )  # AES-256 / SHA1 / RSA / MODP2048
    path = B.write_pcap(tmp_path / "v1_aes.pcap", B.v1_main_mode(sa=sa))
    session = parse_ikev1(path)
    assert session.encryption == "AES-256-CBC"
    assert session.integrity == "HMAC-SHA1"
    assert session.auth_method == "RSA"
    assert session.dh_group == "MODP2048"


def test_xauth_auth_method(main_mode_pcap, tmp_path):
    sa = B.v1_phase1_sa(auth=65001)  # XAUTHInitPreShared
    path = B.write_pcap(tmp_path / "v1_xauth.pcap", B.v1_main_mode(sa=sa))
    assert parse_ikev1(path).auth_method == "XAUTH"


# --------------------------------------------------------------------------- #
# record shape / helpers                                                       #
# --------------------------------------------------------------------------- #


def test_capture_complete_and_metadata(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    assert session.capture_complete is True
    assert session.ip_version == "IPv4"
    assert session.initiator_ip == "192.168.10.1"
    assert session.responder_ip == "192.168.20.1"
    assert session.mode == "tunnel"  # phase-1 only; tunnel/transport is Quick Mode (P2-T3)


def test_vendor_id_recorded(main_mode_pcap):
    session = parse_ikev1(main_mode_pcap)
    assert len(session.vendor_ids) == 1


def test_exchange_mode_name_helper(main_mode_pcap, aggr_pcap):
    assert exchange_mode_name(parse_ikev1(main_mode_pcap)) == "Main Mode"
    assert exchange_mode_name(parse_ikev1(aggr_pcap)) == "Aggressive Mode"


def test_parse_from_raw_bytes():
    session = parse_ikev1(B.v1_aggressive_mode())
    assert session.ike_version == "IKEv1"
    assert session.aggressive_mode is True


def test_no_ikev1_raises():
    with pytest.raises(NoIKEv1Error):
        parse_ikev1([])


def test_ikev2_capture_yields_no_ikev1_session(fixture_pcap):
    assert parse_ikev1_sessions(fixture_pcap("aes256gcm_ecp521_pfs")) == []


def test_mode_detection_survives_capture_starting_after_message_1():
    # only Main Mode messages 3-4 (KE) captured: no SA payload, exchange-type
    # byte still says Main -> not aggressive, capture flagged incomplete
    mm1, _mm2 = B.v1_main_mode()
    ke_only = B._v1_message(B.EXCHANGE_V1_IDENTITY_PROTECT, 0, [(B.V1_PAYLOAD_KE, B._v1_ke())])
    session = parse_ikev1([ke_only])
    assert session.aggressive_mode is False
    assert session.capture_complete is False
