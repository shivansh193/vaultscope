"""Synthetic IKEv2 message + pcap builders for the Stage 2 tests.

The P1 testbed (Stage 0) will eventually supply real strongSwan captures; until
then these hand-rolled RFC 7296 messages keep the parser tests hermetic and
fast. Every byte here is built to the spec so the tests exercise the real
``core.ike_parser._wire`` decoder, not a mock.

IKE_AUTH / CREATE_CHILD_SA inner payloads are placed in the SK payload *in the
clear* -- mirroring a key-logged / tshark-decrypted capture. The decoder's
best-effort SK parser reads them; real ciphertext would stay opaque.
"""

from __future__ import annotations

import struct
from pathlib import Path

from core.ike_parser._transforms import (
    EXCHANGE_CREATE_CHILD_SA,
    EXCHANGE_IKE_AUTH,
    EXCHANGE_IKE_SA_INIT,
    EXCHANGE_V1_AGGRESSIVE,
    EXCHANGE_V1_IDENTITY_PROTECT,
    EXCHANGE_V1_QUICK,
    IKE_VERSION_1,
    NOTIFY_NAT_DETECTION_DESTINATION_IP,
    NOTIFY_NAT_DETECTION_SOURCE_IP,
    NOTIFY_REKEY_SA,
    NOTIFY_USE_TRANSPORT_MODE,
    PAYLOAD_AUTH,
    PAYLOAD_IDI,
    PAYLOAD_KE,
    PAYLOAD_NONCE,
    PAYLOAD_NOTIFY,
    PAYLOAD_SA,
    PAYLOAD_SK,
    PAYLOAD_TSI,
    PAYLOAD_TSR,
    PROTOCOL_ESP,
    PROTOCOL_IKE,
    TRANSFORM_TYPE_DH,
    TRANSFORM_TYPE_ENCR,
    TRANSFORM_TYPE_INTEG,
    TRANSFORM_TYPE_PRF,
    V1_ATTR_AUTH_METHOD,
    V1_ATTR_ENCRYPTION,
    V1_ATTR_GROUP_DESC,
    V1_ATTR_HASH,
    V1_ATTR_KEY_LENGTH,
    V1_ATTR_LIFE_DURATION,
    V1_ATTR_LIFE_TYPE,
    V1_DOI_IPSEC,
    V1_FLAG_ENCRYPTION,
    V1_LIFE_TYPE_SECONDS,
    V1_P2_ATTR_AUTH_ALG,
    V1_P2_ATTR_ENCAP_MODE,
    V1_P2_ATTR_GROUP_DESC,
    V1_P2_ATTR_KEY_LENGTH,
    V1_P2_ATTR_LIFE_DURATION,
    V1_P2_ATTR_LIFE_TYPE,
    V1_PAYLOAD_HASH,
    V1_PAYLOAD_ID,
    V1_PAYLOAD_KE,
    V1_PAYLOAD_NONCE,
    V1_PAYLOAD_SA,
    V1_PAYLOAD_VENDOR_ID,
)

IKE_VERSION_2 = 0x20
FLAG_INITIATOR = 0x08
FLAG_RESPONSE = 0x20

_INIT_SPI = bytes.fromhex("11223344aabbccdd")
_RESP_SPI = bytes.fromhex("99887766ddccbbaa")
_ZERO_SPI = b"\x00" * 8


# --------------------------------------------------------------------------- #
# generic framing                                                              #
# --------------------------------------------------------------------------- #
def _gph(next_payload: int, body: bytes, *, critical: bool = False) -> bytes:
    return struct.pack(">BBH", next_payload, 0x80 if critical else 0, 4 + len(body)) + body


def _chain(payloads: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """payloads = [(payload_type, body), ...] -> (first_type, framed_bytes)."""
    if not payloads:
        return 0, b""
    nexts = [pt for pt, _ in payloads[1:]] + [0]
    out = b"".join(_gph(nxt, body) for (_pt, body), nxt in zip(payloads, nexts))
    return payloads[0][0], out


def _ike_header(
    first_payload: int,
    exch_type: int,
    flags: int,
    message_id: int,
    total_len: int,
    *,
    init_spi: bytes = _INIT_SPI,
    resp_spi: bytes = _RESP_SPI,
) -> bytes:
    return (
        init_spi
        + resp_spi
        + struct.pack(">BBBB", first_payload, IKE_VERSION_2, exch_type, flags)
        + struct.pack(">II", message_id, total_len)
    )


def _message(
    exch_type: int,
    flags: int,
    message_id: int,
    payloads: list[tuple[int, bytes]],
    *,
    init_spi: bytes = _INIT_SPI,
    resp_spi: bytes = _RESP_SPI,
) -> bytes:
    first, body = _chain(payloads)
    return (
        _ike_header(
            first,
            exch_type,
            flags,
            message_id,
            28 + len(body),
            init_spi=init_spi,
            resp_spi=resp_spi,
        )
        + body
    )


def _message_sk(
    exch_type: int,
    flags: int,
    message_id: int,
    inner: list[tuple[int, bytes]],
    *,
    init_spi: bytes = _INIT_SPI,
    resp_spi: bytes = _RESP_SPI,
) -> bytes:
    """HDR + SK{ inner... } with the inner chain left in the clear."""
    inner_first, inner_bytes = _chain(inner)
    sk_payload = struct.pack(">BBH", inner_first, 0, 4 + len(inner_bytes)) + inner_bytes
    return (
        _ike_header(
            PAYLOAD_SK,
            exch_type,
            flags,
            message_id,
            28 + len(sk_payload),
            init_spi=init_spi,
            resp_spi=resp_spi,
        )
        + sk_payload
    )


# --------------------------------------------------------------------------- #
# payload bodies                                                               #
# --------------------------------------------------------------------------- #
def _transform(is_last: bool, ttype: int, tid: int, key_length: int | None = None) -> bytes:
    # RFC 7296 section 3.3.2: "Last Substruc" is 0 for the last transform, 3 if more follow.
    attrs = struct.pack(">HH", 0x8000 | 14, key_length) if key_length is not None else b""
    return struct.pack(">BBHBBH", 0 if is_last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def _proposal(
    num: int,
    protocol_id: int,
    transforms: list[tuple[int, int, int | None]],
    *,
    spi: bytes = b"",
    is_last: bool = True,
) -> bytes:
    tb = b"".join(
        _transform(i == len(transforms) - 1, tt, tid, kl)
        for i, (tt, tid, kl) in enumerate(transforms)
    )
    return (
        struct.pack(
            ">BBHBBBB",
            0 if is_last else 2,
            0,
            8 + len(spi) + len(tb),
            num,
            protocol_id,
            len(spi),
            len(transforms),
        )
        + spi
        + tb
    )


def _sa_ike(encr, prf, integ, dh, *, keylen=None) -> bytes:
    tfs: list[tuple[int, int, int | None]] = [(TRANSFORM_TYPE_ENCR, encr, keylen)]
    if prf is not None:
        tfs.append((TRANSFORM_TYPE_PRF, prf, None))
    if integ:  # 0 / None == AEAD, no INTEG transform
        tfs.append((TRANSFORM_TYPE_INTEG, integ, None))
    if dh:
        tfs.append((TRANSFORM_TYPE_DH, dh, None))
    return _proposal(1, PROTOCOL_IKE, tfs)


def _sa_child_esp(*, dh: int | None = None, encr: int = 20, keylen: int | None = 256) -> bytes:
    tfs: list[tuple[int, int, int | None]] = [(TRANSFORM_TYPE_ENCR, encr, keylen)]
    if dh:
        tfs.append((TRANSFORM_TYPE_DH, dh, None))
    return _proposal(1, PROTOCOL_ESP, tfs, spi=bytes.fromhex("0a0b0c0d"))


# D-H public-value sizes (bytes) -- so a fixture KE payload is the right length
# for its group, the way a real capture is (Stage 4a fingerprints on this).
_DH_KEY_BYTES = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 19: 64, 20: 96, 21: 132, 31: 32}


def _ke(group: int) -> bytes:
    return struct.pack(">HH", group, 0) + b"\xab" * _DH_KEY_BYTES.get(group, 32)


def _nonce() -> bytes:
    return b"\x5a" * 24


def _notify(ntype: int, data: bytes = b"") -> bytes:
    return struct.pack(">BBH", 0, 0, ntype) + data


def _auth(method: int) -> bytes:
    return struct.pack(">B3x", method) + b"\x11" * 16


def _idi_ipv4(addr: bytes = b"\xc0\xa8\x0a\x01") -> bytes:
    return struct.pack(">B3x", 1) + addr  # ID type 1 = ID_IPV4_ADDR


def _ts() -> bytes:
    # 1 TS: type 7 (IPv4 range), proto 0, len 16, ports 0-65535, 0.0.0.0-255.255.255.255
    ts = struct.pack(">BBHHH", 7, 0, 16, 0, 65535) + b"\x00\x00\x00\x00" + b"\xff\xff\xff\xff"
    return struct.pack(">B3x", 1) + ts  # 1 TS follows


# --------------------------------------------------------------------------- #
# exchange builders                                                            #
# --------------------------------------------------------------------------- #
def sa_init_pair(encr, prf, integ, dh, *, keylen=None) -> list[bytes]:
    """IKE_SA_INIT request + response for one negotiated cipher suite."""
    req_payloads = [
        (PAYLOAD_SA, _sa_ike(encr, prf, integ, dh, keylen=keylen)),
        (PAYLOAD_KE, _ke(dh or 19)),
        (PAYLOAD_NONCE, _nonce()),
        (PAYLOAD_NOTIFY, _notify(NOTIFY_NAT_DETECTION_SOURCE_IP, b"\x00" * 20)),
        (PAYLOAD_NOTIFY, _notify(NOTIFY_NAT_DETECTION_DESTINATION_IP, b"\x00" * 20)),
    ]
    resp_payloads = [
        (PAYLOAD_SA, _sa_ike(encr, prf, integ, dh, keylen=keylen)),
        (PAYLOAD_KE, _ke(dh or 19)),
        (PAYLOAD_NONCE, _nonce()),
    ]
    req = _message(EXCHANGE_IKE_SA_INIT, FLAG_INITIATOR, 0, req_payloads, resp_spi=_ZERO_SPI)
    resp = _message(EXCHANGE_IKE_SA_INIT, FLAG_RESPONSE, 0, resp_payloads)
    return [req, resp]


def ike_auth_request(
    *,
    auth_method: int = 2,
    transport: bool = False,
    child_dh: int | None = None,
) -> bytes:
    inner: list[tuple[int, bytes]] = [
        (PAYLOAD_IDI, _idi_ipv4()),
        (PAYLOAD_AUTH, _auth(auth_method)),
        (PAYLOAD_SA, _sa_child_esp(dh=child_dh)),
        (PAYLOAD_TSI, _ts()),
        (PAYLOAD_TSR, _ts()),
    ]
    if transport:
        inner.append((PAYLOAD_NOTIFY, _notify(NOTIFY_USE_TRANSPORT_MODE)))
    return _message_sk(EXCHANGE_IKE_AUTH, FLAG_INITIATOR, 1, inner)


def create_child_sa(
    *, ke_group: int | None = None, dh: int | None = None, rekey: bool = True
) -> bytes:
    inner: list[tuple[int, bytes]] = []
    if rekey:
        inner.append((PAYLOAD_NOTIFY, _notify(NOTIFY_REKEY_SA)))
    inner.append((PAYLOAD_SA, _sa_child_esp(dh=dh)))
    inner.append((PAYLOAD_NONCE, _nonce()))
    if ke_group is not None:
        inner.append((PAYLOAD_KE, _ke(ke_group)))
    inner.append((PAYLOAD_TSI, _ts()))
    inner.append((PAYLOAD_TSR, _ts()))
    return _message_sk(EXCHANGE_CREATE_CHILD_SA, FLAG_INITIATOR, 2, inner)


# --------------------------------------------------------------------------- #
# pcap writers                                                                 #
# --------------------------------------------------------------------------- #
def write_pcap(
    path: str | Path,
    messages: list[bytes],
    *,
    src: str = "192.168.10.1",
    dst: str = "192.168.20.1",
    port: int = 500,
) -> str:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    pkts = []
    for i, m in enumerate(messages):
        s, d = (src, dst) if i % 2 == 0 else (dst, src)
        load = (b"\x00\x00\x00\x00" + m) if port == 4500 else m
        pkts.append(IP(src=s, dst=d) / UDP(sport=port, dport=port) / Raw(load=load))
    wrpcap(str(path), pkts)
    return str(path)


def write_esp_only_pcap(
    path: str | Path, *, src: str = "192.168.10.1", dst: str = "192.168.20.1", n: int = 6
) -> str:
    from scapy.layers.inet import IP
    from scapy.utils import wrpcap

    try:
        from scapy.layers.ipsec import ESP

        pkts = [
            IP(src=src, dst=dst) / ESP(spi=0xDEADBEEF, seq=i + 1, data=b"\x42" * 64)
            for i in range(n)
        ]
    except Exception:  # pragma: no cover
        from scapy.packet import Raw

        pkts = [IP(src=src, dst=dst, proto=50) / Raw(load=b"\x00" * 72) for _ in range(n)]
    wrpcap(str(path), pkts)
    return str(path)


# --------------------------------------------------------------------------- #
# presets for the parametrised cipher test (spec P2-T1)                        #
# --------------------------------------------------------------------------- #
CIPHER_PRESETS: dict[str, dict] = {
    "aes256gcm_ecp521_pfs": dict(
        encr=20, keylen=256, prf=7, integ=0, dh=21, expected_enc="AES-256-GCM", expected_dh="ECP521"
    ),
    "aes128cbc_sha256_modp2048": dict(
        encr=12,
        keylen=128,
        prf=5,
        integ=12,
        dh=14,
        expected_enc="AES-128-CBC",
        expected_dh="MODP2048",
    ),
    "3des_sha1_modp1024": dict(
        encr=3, keylen=None, prf=2, integ=2, dh=2, expected_enc="3DES-CBC", expected_dh="MODP1024"
    ),
}


def sa_init_for_preset(name: str) -> list[bytes]:
    p = CIPHER_PRESETS[name]
    return sa_init_pair(p["encr"], p["prf"], p["integ"], p["dh"], keylen=p["keylen"])


# =========================================================================== #
# IKEv1 / ISAKMP builders (P2-T2)                                              #
# =========================================================================== #
_V1_ICOOKIE = bytes.fromhex("1111111122222222")
_V1_RCOOKIE = bytes.fromhex("3333333344444444")


def _v1_message(
    exch_type: int,
    message_id: int,
    payloads: list[tuple[int, bytes]],
    *,
    icookie: bytes = _V1_ICOOKIE,
    rcookie: bytes = _V1_RCOOKIE,
    flags: int = 0,
) -> bytes:
    first, body = _chain(payloads)
    hdr = (
        icookie
        + rcookie
        + struct.pack(">BBBB", first, IKE_VERSION_1, exch_type, flags)
        + struct.pack(">II", message_id, 28 + len(body))
    )
    return hdr + body


def _v1_tv(attr_type: int, value: int) -> bytes:
    return struct.pack(">HH", 0x8000 | attr_type, value)


def v1_phase1_sa(
    *,
    enc: int = 5,  # 3DES-CBC
    hash_: int = 1,  # MD5
    auth: int = 1,  # PSK
    group: int = 2,  # MODP1024
    keylen: int | None = None,
    life_sec: int | None = 28800,
) -> bytes:
    """A phase-1 ISAKMP SA payload body: DOI + Situation + 1 proposal / 1 transform."""
    attrs = _v1_tv(V1_ATTR_ENCRYPTION, enc) + _v1_tv(V1_ATTR_HASH, hash_)
    attrs += _v1_tv(V1_ATTR_AUTH_METHOD, auth) + _v1_tv(V1_ATTR_GROUP_DESC, group)
    if keylen is not None:
        attrs += _v1_tv(V1_ATTR_KEY_LENGTH, keylen)
    if life_sec is not None:
        attrs += _v1_tv(V1_ATTR_LIFE_TYPE, V1_LIFE_TYPE_SECONDS)
        # Life Duration as TLV (4-byte), the common on-wire encoding
        attrs += struct.pack(">HH", V1_ATTR_LIFE_DURATION, 4) + struct.pack(">I", life_sec)

    # transform: generic hdr(next=0) + [tf#=1, tf-id=1 KEY_IKE, 2 reserved] + attrs
    tf_body = struct.pack(">BBH", 1, 1, 0) + attrs
    transform = struct.pack(">BBH", 0, 0, 4 + len(tf_body)) + tf_body
    # proposal: generic hdr(next=0) + [prop#=1, proto=1 ISAKMP, spi_size=0, #tf=1] + transform
    prop_body = struct.pack(">BBBB", 1, 1, 0, 1) + transform
    proposal = struct.pack(">BBH", 0, 0, 4 + len(prop_body)) + prop_body
    return struct.pack(">II", V1_DOI_IPSEC, 1) + proposal


def _v1_ke() -> bytes:
    return b"\xcc" * 96


def _v1_nonce() -> bytes:
    return b"\x5a" * 20


def _v1_id_ipv4(addr: bytes = b"\xc0\xa8\x01\x01") -> bytes:
    # IPSEC DOI ID payload: ID type(1)=ID_IPV4_ADDR, protocol(1), port(2), data
    return struct.pack(">BBH", 1, 0, 0) + addr


def _v1_hash_payload() -> bytes:
    return b"\x99" * 16


def v1_main_mode(*, sa: bytes | None = None, with_vendor_id: bool = True) -> list[bytes]:
    """Main Mode messages 1-2 (SA offer / SA choice). No ID in msg 1."""
    sa = sa if sa is not None else v1_phase1_sa()
    mm1_payloads = [(V1_PAYLOAD_SA, sa)]
    if with_vendor_id:
        mm1_payloads.append((V1_PAYLOAD_VENDOR_ID, b"\x1e\x2b\x51\x69" * 4))
    mm1 = _v1_message(EXCHANGE_V1_IDENTITY_PROTECT, 0, mm1_payloads, rcookie=b"\x00" * 8)
    mm2 = _v1_message(EXCHANGE_V1_IDENTITY_PROTECT, 0, [(V1_PAYLOAD_SA, sa)])
    return [mm1, mm2]


def v1_aggressive_mode(*, sa: bytes | None = None) -> list[bytes]:
    """Aggressive Mode message 1: SA + KE + Nonce + ID (ID in the clear)."""
    sa = (
        sa if sa is not None else v1_phase1_sa(enc=1, hash_=1, auth=1, group=2)
    )  # DES/MD5/PSK/MODP1024
    am1 = _v1_message(
        EXCHANGE_V1_AGGRESSIVE,
        0,
        [
            (V1_PAYLOAD_SA, sa),
            (V1_PAYLOAD_KE, _v1_ke()),
            (V1_PAYLOAD_NONCE, _v1_nonce()),
            (V1_PAYLOAD_ID, _v1_id_ipv4()),
        ],
        rcookie=b"\x00" * 8,
    )
    am2 = _v1_message(
        EXCHANGE_V1_AGGRESSIVE,
        0,
        [
            (V1_PAYLOAD_SA, sa),
            (V1_PAYLOAD_KE, _v1_ke()),
            (V1_PAYLOAD_NONCE, _v1_nonce()),
            (V1_PAYLOAD_ID, _v1_id_ipv4(b"\xc0\xa8\x02\x01")),
            (V1_PAYLOAD_HASH, _v1_hash_payload()),
        ],
    )
    return [am1, am2]


def v1_main_mode_with_retransmit(*, sa: bytes | None = None) -> list[bytes]:
    """Main Mode 1, 1 (retransmit), 2 -- 3 messages, but not Aggressive Mode."""
    mm1, mm2 = v1_main_mode(sa=sa, with_vendor_id=False)
    return [mm1, mm1, mm2]


# --- IKEv1 Phase 2 / Quick Mode (P2-T3) --------------------------------------
def v1_phase2_sa(
    *,
    esp_id: int = 12,  # ENCR_AES_CBC
    keylen: int | None = 128,
    auth_alg: int = 2,  # HMAC-SHA1
    group: int | None = None,  # set -> PFS with this D-H group
    encap: int = 1,  # 1 = tunnel, 2 = transport
    life_sec: int | None = 3600,
) -> bytes:
    """A Quick Mode (phase-2) ISAKMP SA payload body: DOI + Situation + 1 ESP
    proposal / 1 transform. The transform *id* is the ESP cipher; attributes
    use phase-2 numbering (RFC 2407 section 4.5)."""
    attrs = _v1_tv(V1_P2_ATTR_AUTH_ALG, auth_alg) + _v1_tv(V1_P2_ATTR_ENCAP_MODE, encap)
    if keylen is not None:
        attrs += _v1_tv(V1_P2_ATTR_KEY_LENGTH, keylen)
    if group is not None:
        attrs += _v1_tv(V1_P2_ATTR_GROUP_DESC, group)
    if life_sec is not None:
        attrs += _v1_tv(V1_P2_ATTR_LIFE_TYPE, V1_LIFE_TYPE_SECONDS)
        attrs += struct.pack(">HH", V1_P2_ATTR_LIFE_DURATION, 4) + struct.pack(">I", life_sec)

    # transform: generic hdr(next=0) + [tf#=1, tf-id=<ESP cipher>, 2 reserved] + attrs
    tf_body = struct.pack(">BBH", 1, esp_id, 0) + attrs
    transform = struct.pack(">BBH", 0, 0, 4 + len(tf_body)) + tf_body
    # proposal: generic hdr + [prop#=1, proto=3 ESP, spi_size=4, #tf=1] + SPI + transform
    prop_body = struct.pack(">BBBB", 1, 3, 4, 1) + b"\xde\xad\xbe\xef" + transform
    proposal = struct.pack(">BBH", 0, 0, 4 + len(prop_body)) + prop_body
    return struct.pack(">II", V1_DOI_IPSEC, 1) + proposal


def v1_quick_mode(
    *,
    sa: bytes | None = None,
    with_ke: bool = False,
    message_id: int = 0x0A0B0C0D,
) -> list[bytes]:
    """Quick Mode message 1: HASH + SA + Nonce [+ KE] + IDci + IDcr.

    The ISAKMP ENCRYPTION flag is set (as on the wire); the payload chain is
    left in the clear, mirroring a key-logged / tshark-decrypted capture.
    """
    sa = sa if sa is not None else v1_phase2_sa()
    payloads: list[tuple[int, bytes]] = [
        (V1_PAYLOAD_HASH, _v1_hash_payload()),
        (V1_PAYLOAD_SA, sa),
        (V1_PAYLOAD_NONCE, _v1_nonce()),
    ]
    if with_ke:
        payloads.append((V1_PAYLOAD_KE, _v1_ke()))
    payloads.append((V1_PAYLOAD_ID, _v1_id_ipv4(b"\x0a\x00\x00\x00")))
    payloads.append((V1_PAYLOAD_ID, _v1_id_ipv4(b"\x0a\x00\x01\x00")))
    qm1 = _v1_message(EXCHANGE_V1_QUICK, message_id, payloads, flags=V1_FLAG_ENCRYPTION)
    return [qm1]


def v1_main_then_quick(
    *, p1_sa: bytes | None = None, p2_sa: bytes | None = None, with_ke: bool = False
) -> list[bytes]:
    """A full IKEv1 capture: Main Mode 1-2 then a Quick Mode message."""
    return v1_main_mode(sa=p1_sa) + v1_quick_mode(sa=p2_sa, with_ke=with_ke)
