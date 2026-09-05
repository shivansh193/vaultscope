"""P2-T1 - IKEv2 SA_INIT + IKE_AUTH -> canonical VPNSession extraction.

Mandatory tests from spec Section 9 ("P2-T1: IKEv2 parser"). The parser fills
the ``ike`` block of ``core.models.VPNSession`` (one session shape for the
whole pipeline), so assertions read ``session.ike.<field>``.
"""

from __future__ import annotations

import _build as B
import pytest

from core.ike_parser import (
    NoIKEv2Error,
    VPNSession,
    decode_message,
    parse_ikev2,
    parse_ikev2_sessions,
)
from core.ike_parser._transforms import EXCHANGE_IKE_SA_INIT
from core.models import VPNSession as CanonicalVPNSession

# --------------------------------------------------------------------------- #
# spec P2-T1 mandatory tests                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "cipher,expected_enc,expected_dh",
    [
        ("aes256gcm_ecp521_pfs", "AES-256-GCM", "ECP521"),
        ("aes128cbc_sha256_modp2048", "AES-128-CBC", "MODP2048"),
        ("3des_sha1_modp1024", "3DES-CBC", "MODP1024"),
    ],
)
def test_ikev2_cipher_extraction(cipher, expected_enc, expected_dh, fixture_pcap):
    session = parse_ikev2(fixture_pcap(cipher))
    assert session.ike.encryption == expected_enc
    assert session.ike.dh_group == expected_dh


def test_ikev2_pfs_enabled(pfs_pcap_fixture):
    assert parse_ikev2(pfs_pcap_fixture).ike.pfs_status == "enabled"


def test_ikev2_pfs_disabled(no_pfs_pcap_fixture):
    assert parse_ikev2(no_pfs_pcap_fixture).ike.pfs_status == "disabled"


def test_ikev2_transport_mode(transport_pcap_fixture):
    assert parse_ikev2(transport_pcap_fixture).ike.mode == "transport"


def test_mid_session_pfs_unknown(esp_only_fixture):
    session = parse_ikev2(esp_only_fixture)
    assert session.ike.pfs_status == "unknown"  # NOT "disabled"


# --------------------------------------------------------------------------- #
# transform canonicalisation                                                   #
# --------------------------------------------------------------------------- #


def test_aead_suite_has_implicit_integrity(fixture_pcap):
    session = parse_ikev2(fixture_pcap("aes256gcm_ecp521_pfs"))
    assert session.ike.integrity == "implicit"  # canonical AEAD string
    assert session.ike.prf == "PRF_HMAC_SHA2_512"


def test_cbc_suite_reports_hmac_integrity(fixture_pcap):
    session = parse_ikev2(fixture_pcap("aes128cbc_sha256_modp2048"))
    assert session.ike.integrity == "HMAC-SHA256"
    assert session.ike.prf == "PRF_HMAC_SHA2_256"


def test_weak_suite_canonical_names(fixture_pcap):
    ike = parse_ikev2(fixture_pcap("3des_sha1_modp1024")).ike
    assert (ike.encryption, ike.integrity, ike.dh_group) == ("3DES-CBC", "HMAC-SHA1", "MODP1024")


# --------------------------------------------------------------------------- #
# IKE_AUTH extraction                                                          #
# --------------------------------------------------------------------------- #


def test_ike_auth_psk_method(transport_pcap_fixture):
    assert parse_ikev2(transport_pcap_fixture).ike.auth_method == "PSK"


def test_ike_auth_rsa_method_and_tunnel_default(tunnel_pcap_fixture):
    ike = parse_ikev2(tunnel_pcap_fixture).ike
    assert ike.auth_method == "RSA"
    assert ike.mode == "tunnel"


def test_initial_child_sa_with_dh_enables_pfs(tunnel_pcap_fixture):
    # tunnel fixture's IKE_AUTH child SA carries D-H group 19
    assert parse_ikev2(tunnel_pcap_fixture).ike.pfs_status == "enabled"


# --------------------------------------------------------------------------- #
# session record shape / provenance                                           #
# --------------------------------------------------------------------------- #


def test_returns_canonical_vpnsession(fixture_pcap):
    session = parse_ikev2(fixture_pcap("aes256gcm_ecp521_pfs"))
    assert isinstance(session, CanonicalVPNSession)
    # round-trips through the pipeline's serialisation
    assert session.model_dump()["ike"]["encryption"] == "AES-256-GCM"


def test_session_id_is_spi_pair(fixture_pcap):
    session = parse_ikev2(fixture_pcap("aes256gcm_ecp521_pfs"))
    init_hex, resp_hex = session.session_id.split("-")
    assert init_hex == "11223344aabbccdd"
    assert resp_hex == "99887766ddccbbaa"


def test_capture_complete_and_ip_metadata(fixture_pcap):
    session = parse_ikev2(fixture_pcap("aes256gcm_ecp521_pfs"))
    assert session.ike.capture_complete is True
    assert session.ike.version == "IKEv2"
    assert session.ike.ip_version == "IPv4"
    assert session.initiator_ip == "192.168.10.1"
    assert session.responder_ip == "192.168.20.1"


def test_nat_t_capture_on_4500_parses(nat_t_pcap_fixture):
    ike = parse_ikev2(nat_t_pcap_fixture).ike
    assert ike.encryption == "AES-128-CBC"
    assert ike.dh_group == "MODP2048"
    assert ike.nat_traversal is True


def test_mid_session_capture_flagged_incomplete(esp_only_fixture):
    assert parse_ikev2(esp_only_fixture).ike.capture_complete is False


def test_esp_only_source_still_returns_one_session(esp_only_fixture):
    sessions = parse_ikev2_sessions(esp_only_fixture)
    assert len(sessions) == 1
    assert sessions[0].ike.version == "IKEv2"


def test_no_ikev2_and_no_esp_raises():
    with pytest.raises(NoIKEv2Error):
        parse_ikev2([])


# --------------------------------------------------------------------------- #
# accepts pre-decoded messages / raw bytes, not just pcap paths                #
# --------------------------------------------------------------------------- #


def test_parse_from_raw_message_bytes():
    session = parse_ikev2(B.sa_init_for_preset("aes256gcm_ecp521_pfs"))  # list[bytes]
    assert session.ike.encryption == "AES-256-GCM"
    assert session.ike.dh_group == "ECP521"
    assert session.ike.pfs_status == "unknown"  # no IKE_AUTH / CREATE_CHILD_SA seen


def test_two_ike_sas_bucketed_separately():
    a = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    b = B.sa_init_pair(12, 5, 12, 14, keylen=128)
    b = [
        m.replace(B._INIT_SPI, bytes.fromhex("aaaaaaaaaaaaaaaa")).replace(
            B._RESP_SPI, bytes.fromhex("bbbbbbbbbbbbbbbb")
        )
        for m in b
    ]
    sessions = parse_ikev2_sessions(a + b)
    assert len(sessions) == 2
    assert {s.ike.encryption for s in sessions} == {"AES-256-GCM", "AES-128-CBC"}


# --------------------------------------------------------------------------- #
# raw wire decoder                                                             #
# --------------------------------------------------------------------------- #


def test_decode_message_header_fields():
    req, _resp = B.sa_init_for_preset("3des_sha1_modp1024")
    msg = decode_message(req)
    assert msg.is_ikev2
    assert msg.exchange_type == EXCHANGE_IKE_SA_INIT
    assert msg.is_initiator and not msg.is_response
    assert msg.initiator_spi.hex() == "11223344aabbccdd"
    assert msg.responder_spi == b"\x00" * 8  # zero in the first request


def test_decode_sk_plaintext_is_readable():
    auth = B.ike_auth_request(auth_method=2, transport=True)
    msg = decode_message(auth)
    sk = msg.payloads[0]
    assert sk.type == 46
    assert sk.sk_opaque is False
    assert [p.type for p in sk.inner][:2] == [35, 39]  # IDi, AUTH


def test_decode_opaque_sk_when_not_plaintext():
    # a real SK body (random bytes) must not frame as a payload chain
    import struct

    garbage = b"\xde\xad\xbe\xef" * 12
    sk_payload = struct.pack(">BBH", 35, 0, 4 + len(garbage)) + garbage
    raw = (
        B._INIT_SPI
        + B._RESP_SPI
        + struct.pack(">BBBB", 46, 0x20, 35, 0x08)
        + struct.pack(">II", 1, 28 + len(sk_payload))
        + sk_payload
    )
    msg = decode_message(raw)
    assert msg.payloads[0].sk_opaque is True


def test_public_vpnsession_is_the_canonical_model():
    assert VPNSession is CanonicalVPNSession
