"""Byte-level IKEv2 message decoder (RFC 7296).

Pure ``struct`` parsing, no scapy/pyshark dependency, so the interesting logic
(transform selection, PFS detection, transport-mode notify) is unit-testable
against synthetic messages.

Scope: the cleartext payloads that carry the negotiated parameters -- SA, KE,
NONCE, NOTIFY, AUTH, IDi/IDr, VENDOR ID, TSi/TSr, and the SK envelope.

SK handling
-----------
The Encrypted-and-Authenticated (SK) payload is ciphertext without the
SK_e keys. Captures produced with key logging (strongSwan ``charon`` /
``SSLKEYLOGFILE`` style) or dissected by tshark with an
``ikev2_decryption_table`` expose the plaintext inner payloads. This decoder
therefore makes a *best effort*: it tries to parse the SK content as a payload
chain; if that does not consume the content exactly and validly it marks the
SK payload ``opaque`` and callers fall back to "unknown" for any field that
would have come from inside it. See ``_try_parse_chain``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ._transforms import (
    ATTR_KEY_LENGTH,
    PAYLOAD_AUTH,
    PAYLOAD_IDI,
    PAYLOAD_IDR,
    PAYLOAD_KE,
    PAYLOAD_NOTIFY,
    PAYLOAD_SA,
    PAYLOAD_SK,
    TRANSFORM_TYPE_DH,
)

IKE_HEADER_LEN = 28
IKE_VERSION_2 = 0x20
IKE_VERSION_1 = 0x10

# IKEv2 header flags (RFC 7296 section 3.1)
FLAG_INITIATOR = 0x08
FLAG_VERSION = 0x10
FLAG_RESPONSE = 0x20

# ISAKMP / IKEv1 header flags (RFC 2408 section 3.1)
V1_FLAG_ENCRYPTION = 0x01


class WireFormatError(ValueError):
    """Raised when bytes do not conform to the RFC 7296 wire format."""


@dataclass
class Transform:
    type: int
    id: int
    key_length: int | None = None  # bits, from the Key Length attribute


@dataclass
class Proposal:
    number: int
    protocol_id: int
    spi: bytes
    transforms: list[Transform] = field(default_factory=list)

    def first(self, transform_type: int) -> Transform | None:
        for t in self.transforms:
            if t.type == transform_type:
                return t
        return None

    def has_dh(self) -> bool:
        """True when the proposal carries a real (non-NONE) D-H group."""
        t = self.first(TRANSFORM_TYPE_DH)
        return t is not None and t.id != 0


@dataclass
class Payload:
    type: int
    critical: bool
    raw: bytes  # payload body, excluding the 4-byte generic header

    # populated per-type by the decoder
    proposals: list[Proposal] = field(default_factory=list)  # SA
    dh_group: int | None = None  # KE
    notify_type: int | None = None  # NOTIFY
    notify_protocol_id: int | None = None  # NOTIFY
    notify_spi: bytes = b""  # NOTIFY
    notify_data: bytes = b""  # NOTIFY
    auth_method: int | None = None  # AUTH
    id_type: int | None = None  # IDi / IDr
    id_data: bytes = b""  # IDi / IDr
    sk_opaque: bool = True  # SK: True when inner plaintext was not recoverable
    inner: list[Payload] = field(default_factory=list)  # SK: decrypted chain


@dataclass
class IkeMessage:
    initiator_spi: bytes
    responder_spi: bytes
    next_payload: int
    version: int
    exchange_type: int
    flags: int
    message_id: int
    length: int
    payloads: list[Payload] = field(default_factory=list)
    truncated: bool = False  # declared length > bytes available
    encrypted: bool = False  # IKEv1 message with the ENCRYPTION flag set -> body not framed

    # --- flag helpers ---
    @property
    def is_initiator(self) -> bool:
        return bool(self.flags & FLAG_INITIATOR)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def is_ikev2(self) -> bool:
        return self.version == IKE_VERSION_2

    @property
    def is_ikev1(self) -> bool:
        return self.version == IKE_VERSION_1

    def find(self, payload_type: int, *, deep: bool = True) -> list[Payload]:
        """All payloads of a type, descending into a decrypted SK by default."""
        out: list[Payload] = []
        for p in self.payloads:
            if p.type == payload_type:
                out.append(p)
            if deep and p.type == PAYLOAD_SK and not p.sk_opaque:
                out.extend(ip for ip in p.inner if ip.type == payload_type)
        return out

    def first(self, payload_type: int, *, deep: bool = True) -> Payload | None:
        found = self.find(payload_type, deep=deep)
        return found[0] if found else None

    def all_payloads(self) -> list[Payload]:
        """Flatten top-level payloads plus any decrypted SK inner payloads."""
        out: list[Payload] = []
        for p in self.payloads:
            out.append(p)
            if p.type == PAYLOAD_SK and not p.sk_opaque:
                out.extend(p.inner)
        return out


# --------------------------------------------------------------------------- #
# transform attributes                                                         #
# --------------------------------------------------------------------------- #
def _parse_transform_attributes(blob: bytes) -> dict[int, int]:
    """Return {attribute_type: value}. Only fixed-length (TV) attrs are kept."""
    attrs: dict[int, int] = {}
    off = 0
    while off + 4 <= len(blob):
        af_type, val = struct.unpack_from(">HH", blob, off)
        is_tv = bool(af_type & 0x8000)
        attr_type = af_type & 0x7FFF
        if is_tv:
            attrs[attr_type] = val
            off += 4
        else:
            # TLV: val is the length of the value that follows
            off += 4 + val
    return attrs


def _parse_sa(body: bytes) -> list[Proposal]:
    proposals: list[Proposal] = []
    off = 0
    while off + 8 <= len(body):
        last, _res, prop_len, prop_num, proto_id, spi_size, n_transforms = struct.unpack_from(
            ">BBHBBBB", body, off
        )
        if prop_len < 8 or off + prop_len > len(body):
            raise WireFormatError("SA proposal length out of range")
        spi = body[off + 8 : off + 8 + spi_size]
        prop = Proposal(number=prop_num, protocol_id=proto_id, spi=spi)

        toff = off + 8 + spi_size
        end = off + prop_len
        seen = 0
        while toff + 8 <= end:
            t_last, _tr, t_len, t_type, _tr2, t_id = struct.unpack_from(">BBHBBH", body, toff)
            if t_len < 8 or toff + t_len > end:
                raise WireFormatError("SA transform length out of range")
            attrs = _parse_transform_attributes(body[toff + 8 : toff + t_len])
            prop.transforms.append(
                Transform(type=t_type, id=t_id, key_length=attrs.get(ATTR_KEY_LENGTH))
            )
            seen += 1
            toff += t_len
            if t_last == 0:
                break
        if n_transforms and seen != n_transforms:
            # tolerate but do not fail: malformed captures happen
            pass

        proposals.append(prop)
        off += prop_len
        if last == 0:
            break
    return proposals


def _parse_ke(body: bytes) -> int | None:
    if len(body) < 4:
        raise WireFormatError("KE payload too short")
    (group,) = struct.unpack_from(">H", body, 0)
    return group


def _parse_notify(body: bytes) -> tuple[int, int, bytes, bytes]:
    if len(body) < 4:
        raise WireFormatError("NOTIFY payload too short")
    proto_id, spi_size, ntype = struct.unpack_from(">BBH", body, 0)
    spi = body[4 : 4 + spi_size]
    data = body[4 + spi_size :]
    return ntype, proto_id, spi, data


def _parse_auth(body: bytes) -> int:
    if len(body) < 4:
        raise WireFormatError("AUTH payload too short")
    return body[0]


def _parse_id(body: bytes) -> tuple[int, bytes]:
    if len(body) < 4:
        raise WireFormatError("ID payload too short")
    return body[0], body[4:]


def _decorate(p: Payload) -> Payload:
    """Fill the per-type fields on a freshly framed payload. Never raises for
    unknown types; structural errors in known types propagate."""
    if p.type == PAYLOAD_SA:
        p.proposals = _parse_sa(p.raw)
    elif p.type == PAYLOAD_KE:
        p.dh_group = _parse_ke(p.raw)
    elif p.type == PAYLOAD_NOTIFY:
        p.notify_type, p.notify_protocol_id, p.notify_spi, p.notify_data = _parse_notify(p.raw)
    elif p.type == PAYLOAD_AUTH:
        p.auth_method = _parse_auth(p.raw)
    elif p.type in (PAYLOAD_IDI, PAYLOAD_IDR):
        p.id_type, p.id_data = _parse_id(p.raw)
    return p


def _frame_chain(data: bytes, first_next_payload: int) -> list[Payload]:
    """Split a byte string into generic-header-framed payloads.

    Raises WireFormatError on any structural inconsistency so the SK best-effort
    parser can reject ciphertext cleanly.
    """
    payloads: list[Payload] = []
    nxt = first_next_payload
    off = 0
    while nxt != 0:
        if off + 4 > len(data):
            raise WireFormatError("payload header past end of buffer")
        this_next, crit_res, plen = struct.unpack_from(">BBH", data, off)
        if plen < 4 or off + plen > len(data):
            raise WireFormatError("payload length past end of buffer")
        body = data[off + 4 : off + plen]
        p = Payload(type=nxt, critical=bool(crit_res & 0x80), raw=body)
        payloads.append(_decorate(p))
        nxt = this_next
        off += plen
    if off != len(data):
        raise WireFormatError("trailing bytes after payload chain")
    return payloads


def _try_parse_sk_plaintext(sk_body: bytes, first_next_payload: int) -> list[Payload] | None:
    """Best-effort: is ``sk_body`` an unencrypted inner payload chain?

    Synthetic fixtures and key-logged captures put readable payloads here.
    Real ciphertext will (almost) never frame cleanly -> return None.
    """
    try:
        return _frame_chain(sk_body, first_next_payload)
    except WireFormatError:
        return None


def decode_message(raw: bytes) -> IkeMessage:
    """Decode one IKE message (28-byte header + payloads). IKEv1 or IKEv2."""
    if len(raw) < IKE_HEADER_LEN:
        raise WireFormatError(f"IKE message shorter than header ({len(raw)} bytes)")

    init_spi = raw[0:8]
    resp_spi = raw[8:16]
    next_payload, version, exch_type, flags = struct.unpack_from(">BBBB", raw, 16)
    (message_id,) = struct.unpack_from(">I", raw, 20)
    (length,) = struct.unpack_from(">I", raw, 24)

    msg = IkeMessage(
        initiator_spi=init_spi,
        responder_spi=resp_spi,
        next_payload=next_payload,
        version=version,
        exchange_type=exch_type,
        flags=flags,
        message_id=message_id,
        length=length,
    )

    body = raw[IKE_HEADER_LEN:]
    if length and length > len(raw):
        msg.truncated = True

    # IKEv1 Main Mode messages 5-6 (and all later phases) are encrypted under
    # SKEYID_e: the payload area is ciphertext, not framable. Leave payloads
    # empty rather than manufacturing garbage from it.
    if version == IKE_VERSION_1 and (flags & V1_FLAG_ENCRYPTION):
        msg.encrypted = True
        return msg

    nxt = next_payload
    off = 0
    while nxt != 0:
        if off + 4 > len(body):
            msg.truncated = True
            break
        this_next, crit_res, plen = struct.unpack_from(">BBH", body, off)
        if plen < 4 or off + plen > len(body):
            msg.truncated = True
            break
        payload_body = body[off + 4 : off + plen]

        if nxt == PAYLOAD_SK:
            sk = Payload(type=PAYLOAD_SK, critical=bool(crit_res & 0x80), raw=payload_body)
            inner = _try_parse_sk_plaintext(payload_body, this_next)
            if inner is not None:
                sk.sk_opaque = False
                sk.inner = inner
            msg.payloads.append(sk)
            # SK is always the last payload; its `next_payload` describes the
            # first *inner* payload, not another top-level one.
            break

        p = Payload(type=nxt, critical=bool(crit_res & 0x80), raw=payload_body)
        try:
            _decorate(p)
        except WireFormatError:
            # keep the framed payload; drop the structured view
            pass
        msg.payloads.append(p)
        nxt = this_next
        off += plen

    return msg
