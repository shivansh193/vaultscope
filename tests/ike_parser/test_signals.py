"""Extended IKE signals: DPD, retransmission timing, peer certificate.

Feeds rules R16 (expired cert), R17 (DPD off), R18 (IKEv1/IPv6).
"""

from __future__ import annotations

import datetime as dt

import _build as B
import pytest

from core.ike_parser import parse_ikev1, parse_ikev2
from core.ike_parser._signals import (
    cert_from_messages,
    dpd_from_messages,
    retransmit_interval_ms,
)
from core.ike_parser._wire import decode_message

_DPD_VID = bytes.fromhex("afcad71368a1f1c96b8696fc77570100")


# --------------------------------------------------------------------------- #
# Dead Peer Detection                                                          #
# --------------------------------------------------------------------------- #


def test_dpd_enabled_from_vid(tmp_path):
    sa = B.v1_phase1_sa()
    mm1 = B._v1_message(
        B.EXCHANGE_V1_IDENTITY_PROTECT,
        0,
        [(B.V1_PAYLOAD_SA, sa), (B.V1_PAYLOAD_VENDOR_ID, _DPD_VID)],
        rcookie=b"\x00" * 8,
    )
    mm2 = B._v1_message(B.EXCHANGE_V1_IDENTITY_PROTECT, 0, [(B.V1_PAYLOAD_SA, sa)])
    session = parse_ikev1(B.write_pcap(tmp_path / "dpd.pcap", [mm1, mm2]))
    assert session.ike.dpd_status == "enabled"


def test_dpd_disabled_for_complete_ikev1_without_vid(main_mode_pcap):
    assert parse_ikev1(main_mode_pcap).ike.dpd_status == "disabled"


def test_dpd_unknown_for_ikev2_sa_init_only(fixture_pcap):
    assert parse_ikev2(fixture_pcap("aes256gcm_ecp521_pfs")).ike.dpd_status == "unknown"


def test_dpd_helper_empty():
    assert dpd_from_messages([]) == ("unknown", None)


# --------------------------------------------------------------------------- #
# retransmission timing                                                        #
# --------------------------------------------------------------------------- #


def test_retransmit_interval_median():
    key = (34, 0, False)
    times = [(key, 0.0), (key, 3.0), (key, 6.1), (key, 9.0)]  # ~3s apart
    assert retransmit_interval_ms(times) == pytest.approx(3000, abs=100)


def test_retransmit_interval_none_without_repeats():
    assert retransmit_interval_ms([((34, 0, False), 1.0)]) is None
    assert retransmit_interval_ms(None) is None


def test_retransmit_interval_from_pcap(tmp_path):
    req, resp = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    # write req three times ~10s apart (Cisco-like), then the response
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    frames = []
    for i, t in enumerate((0.0, 10.0, 20.1)):
        p = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(req)
        p.time = 1_000_000.0 + t
        frames.append(p)
    r = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=500, dport=500) / Raw(resp)
    r.time = 1_000_030.0
    frames.append(r)
    path = str(tmp_path / "rtx.pcap")
    wrpcap(path, frames)

    ike = parse_ikev2(path).ike
    assert ike.retransmit_interval_ms is not None
    assert 8000 <= ike.retransmit_interval_ms <= 12000  # ~10s


# --------------------------------------------------------------------------- #
# peer certificate                                                             #
# --------------------------------------------------------------------------- #


def _self_signed(*, days_valid: int, key_bits: int = 2048) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpn.example.gov")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=400))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _ike_auth_with_cert(der: bytes) -> bytes:
    # SK{ IDi, CERT (enc=4 X.509), AUTH } -- CERT payload type 37
    inner = [
        (B.PAYLOAD_IDI, B._idi_ipv4()),
        (37, b"\x04" + der),
        (B.PAYLOAD_AUTH, B._auth(1)),  # RSA
    ]
    return B._message_sk(B.EXCHANGE_IKE_AUTH, B.FLAG_INITIATOR, 1, inner)


def test_expired_cert_parsed_and_flagged(tmp_path):
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(_ike_auth_with_cert(_self_signed(days_valid=-5)))
    session = parse_ikev2(B.write_pcap(tmp_path / "cert.pcap", msgs))
    assert session.ike.cert is not None
    assert session.ike.cert.expired is True
    assert session.ike.cert.key_bits == 2048
    assert session.ike.cert.self_signed is True
    assert "example.gov" in session.ike.cert.subject


def test_valid_cert_not_flagged(tmp_path):
    msgs = B.sa_init_for_preset("aes256gcm_ecp521_pfs")
    msgs.append(_ike_auth_with_cert(_self_signed(days_valid=365)))
    cert = parse_ikev2(B.write_pcap(tmp_path / "cert_ok.pcap", msgs)).ike.cert
    assert cert is not None and cert.expired is False


def test_no_cert_payload_leaves_none(fixture_pcap):
    assert parse_ikev2(fixture_pcap("aes256gcm_ecp521_pfs")).ike.cert is None


def test_cert_helper_ignores_non_x509(tmp_path):
    m = decode_message(
        B._message_sk(B.EXCHANGE_IKE_AUTH, B.FLAG_INITIATOR, 1, [(37, b"\x01garbage")])
    )
    assert cert_from_messages([m]) is None
