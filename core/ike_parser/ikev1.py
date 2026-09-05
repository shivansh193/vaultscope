"""Stage 2 - IKEv1 / ISAKMP handshake reconstruction (P2-T2, P2-T3).

``parse_ikev1(source)`` turns an IKEv1 exchange into a canonical
:class:`core.models.VPNSession` (fills the ``ike`` block).

Mode detection (spec Section 4, "IKEv1 Message Handling")
--------------------------------------------------------
Aggressive Mode is flagged when the phase-1 *initial* message (the one carrying
the SA payload, message-id 0) also carries an Identification payload -- in
Aggressive Mode the ID travels in message 1 in the clear (that is the whole
weakness: the PSK authentication hash is exposed and offline-crackable).
Message *count* is deliberately not used: retransmissions change it. The
ISAKMP exchange-type byte (2 = Main, 4 = Aggressive) is the fallback when no
SA-bearing message is in the capture.

Phase 1 (Main / Aggressive Mode) -> IKE SA
-----------------------------------------
From the first proposal's first transform of the phase-1 SA payload:
encryption, hash -> integrity + prf, auth method (PSK / RSA / DSS / XAUTH),
D-H group, SA lifetime. NAT-D presence -> nat_traversal.

Phase 2 (Quick Mode) -> IPsec SA  (P2-T3)
----------------------------------------
Quick Mode is encrypted; readable only for key-logged / tshark-decrypted
captures (and synthetic fixtures) -- ``_wire`` best-effort frames the body.
When a QM SA is observed it *overrides* the phase-1 crypto fields, because the
IPsec SA is what actually protects data and is what the Stage 4c rule engine
should evaluate:

  * ``encryption`` / ``integrity`` from the ESP transform id + Auth Algorithm
  * ``dh_group`` from the QM Group Description (if PFS)
  * ``mode`` (tunnel / transport) from the Encapsulation Mode attribute
  * ``pfs_status`` = enabled if a KE payload or Group Description is present,
    disabled if an observed QM negotiation has neither, ``unknown`` if no Quick
    Mode was captured (never guessed -- spec Section 12 / rule R10).
"""

from __future__ import annotations

import struct

from core.models import IkeParams, VPNSession

from ._transforms import (
    EXCHANGE_V1_AGGRESSIVE,
    EXCHANGE_V1_IDENTITY_PROTECT,
    EXCHANGE_V1_NAMES,
    EXCHANGE_V1_QUICK,
    V1_ATTR_AUTH_METHOD,
    V1_ATTR_ENCRYPTION,
    V1_ATTR_GROUP_DESC,
    V1_ATTR_HASH,
    V1_ATTR_KEY_LENGTH,
    V1_ATTR_LIFE_DURATION,
    V1_ATTR_LIFE_TYPE,
    V1_ENCAP_TRANSPORT,
    V1_ENCAP_TUNNEL,
    V1_ENCAP_UDP_TRANSPORT,
    V1_ENCAP_UDP_TUNNEL,
    V1_LIFE_TYPE_SECONDS,
    V1_P2_ATTR_AUTH_ALG,
    V1_P2_ATTR_ENCAP_MODE,
    V1_P2_ATTR_GROUP_DESC,
    V1_P2_ATTR_KEY_LENGTH,
    V1_P2_ATTR_LIFE_DURATION,
    V1_P2_ATTR_LIFE_TYPE,
    V1_PAYLOAD_ID,
    V1_PAYLOAD_KE,
    V1_PAYLOAD_NAT_D,
    V1_PAYLOAD_NAT_D_DRAFT,
    V1_PAYLOAD_SA,
    canon_dh_group,
    canon_v1_auth_method,
    canon_v1_encryption,
    canon_v1_esp_encryption,
    canon_v1_esp_integrity,
    canon_v1_integrity,
    canon_v1_prf,
)
from ._wire import IkeMessage, WireFormatError
from .ikev2 import _normalise, apply_edge_cases  # shared pcap / source ingestion

_ZERO_COOKIE = b"\x00" * 8


class NoIKEv1Error(ValueError):
    """No IKEv1 messages were found in the source."""


# --------------------------------------------------------------------------- #
# IKEv1 SA payload -> attributes                                               #
# --------------------------------------------------------------------------- #
def _parse_v1_attributes(blob: bytes) -> dict[int, int]:
    """ISAKMP SA attributes (RFC 2408 3.3). TV -> the 2-byte value; TLV -> the
    value decoded as a big-endian int when <= 8 bytes (covers Life Duration)."""
    attrs: dict[int, int] = {}
    off = 0
    while off + 4 <= len(blob):
        af_type = int.from_bytes(blob[off : off + 2], "big")
        is_tv = bool(af_type & 0x8000)
        atype = af_type & 0x7FFF
        if is_tv:
            attrs[atype] = int.from_bytes(blob[off + 2 : off + 4], "big")
            off += 4
        else:
            alen = int.from_bytes(blob[off + 2 : off + 4], "big")
            val = blob[off + 4 : off + 4 + alen]
            if 0 < len(val) <= 8:
                attrs[atype] = int.from_bytes(val, "big")
            off += 4 + alen
    return attrs


def _first_transform(sa_body: bytes) -> tuple[int, int, dict[int, int]]:
    """(proposal protocol-id, transform-id, attrs) for the first transform of
    the first proposal in an ISAKMP SA payload body (DOI + Situation +
    Proposal(s) -> Transform(s)). Works for phase 1 and phase 2 -- only the
    caller knows how to read the transform-id / attribute numbers."""
    if len(sa_body) < 8:
        raise WireFormatError("IKEv1 SA payload too short for DOI + situation")
    # sa_body[0:4] = DOI, sa_body[4:8] = Situation (IPSEC DOI). Proposals follow.
    off = 8
    if off + 8 > len(sa_body):
        raise WireFormatError("IKEv1 SA payload has no proposal")
    _p_next, _res, p_len = struct.unpack_from(">BBH", sa_body, off)
    if p_len < 8 or off + p_len > len(sa_body):
        raise WireFormatError("IKEv1 proposal length out of range")
    prop = sa_body[off + 4 : off + p_len]  # after the 4-byte generic header
    # prop: 1 num, 1 protocol-id, 1 spi-size, 1 #transforms, SPI, transforms
    protocol_id = prop[1]
    spi_size = prop[2]
    toff = 4 + spi_size
    if toff + 8 > len(prop):
        raise WireFormatError("IKEv1 proposal has no transform")
    _t_next, _tres, t_len = struct.unpack_from(">BBH", prop, toff)
    if t_len < 8 or toff + t_len > len(prop):
        raise WireFormatError("IKEv1 transform length out of range")
    # transform body after 4-byte generic header: 1 num, 1 id, 2 reserved, attrs
    tbody = prop[toff + 4 : toff + t_len]
    transform_id = tbody[1]
    return protocol_id, transform_id, _parse_v1_attributes(tbody[4:])


# --------------------------------------------------------------------------- #
# analysis                                                                     #
# --------------------------------------------------------------------------- #
def _phase1_initial(messages: list[IkeMessage]) -> IkeMessage | None:
    """The SA-bearing opening message (message-id 0 with an SA payload)."""
    candidates = [
        m
        for m in messages
        if m.message_id == 0 and any(p.type == V1_PAYLOAD_SA for p in m.payloads)
    ]
    if not candidates:
        return None
    # earliest in capture order is the initiator's; retransmits are identical
    return candidates[0]


def _apply_phase1_sa(ike: dict, attrs: dict[int, int]) -> None:
    enc = attrs.get(V1_ATTR_ENCRYPTION)
    keylen = attrs.get(V1_ATTR_KEY_LENGTH)
    h = attrs.get(V1_ATTR_HASH)
    auth = attrs.get(V1_ATTR_AUTH_METHOD)
    group = attrs.get(V1_ATTR_GROUP_DESC)

    if enc is not None:
        ike["encryption"] = canon_v1_encryption(enc, keylen)
    if h is not None:
        ike["integrity"] = canon_v1_integrity(h)
        ike["prf"] = canon_v1_prf(h)
    if auth is not None:
        am = canon_v1_auth_method(auth)
        if am is not None:
            ike["auth_method"] = am
    if group is not None:
        ike["dh_group"] = canon_dh_group(group)

    life_type = attrs.get(V1_ATTR_LIFE_TYPE)
    life = attrs.get(V1_ATTR_LIFE_DURATION)
    if life is not None and life_type in (None, V1_LIFE_TYPE_SECONDS):
        ike["sa_lifetime_sec"] = life


def _quick_mode_sa(messages: list[IkeMessage]):
    """First Quick Mode (exchange type 32) message carrying a phase-2 SA
    payload, plus whether that message also carries a KE payload."""
    for m in messages:
        if m.exchange_type != EXCHANGE_V1_QUICK:
            continue
        sa = next((p for p in m.payloads if p.type == V1_PAYLOAD_SA), None)
        if sa is not None:
            has_ke = any(p.type == V1_PAYLOAD_KE for p in m.payloads)
            return sa, has_ke
    return None, False


def _apply_quick_mode(ike: dict, sa_body: bytes, has_ke: bool) -> None:
    """Phase-2 (IPsec SA) parameters from a Quick Mode SA payload. For IKEv1
    these *override* the phase-1 crypto fields: the IPsec SA is what actually
    protects data, so that is what the rule engine should see."""
    _proto, transform_id, attrs = _first_transform(sa_body)

    ike["encryption"] = canon_v1_esp_encryption(transform_id, attrs.get(V1_P2_ATTR_KEY_LENGTH))
    auth_alg = attrs.get(V1_P2_ATTR_AUTH_ALG)
    if auth_alg is not None:
        ike["integrity"] = canon_v1_esp_integrity(auth_alg)

    group = attrs.get(V1_P2_ATTR_GROUP_DESC)
    if group:
        ike["dh_group"] = canon_dh_group(group)

    encap = attrs.get(V1_P2_ATTR_ENCAP_MODE)
    if encap in (V1_ENCAP_TRANSPORT, V1_ENCAP_UDP_TRANSPORT):
        ike["mode"] = "transport"
    elif encap in (V1_ENCAP_TUNNEL, V1_ENCAP_UDP_TUNNEL):
        ike["mode"] = "tunnel"

    life_type = attrs.get(V1_P2_ATTR_LIFE_TYPE)
    life = attrs.get(V1_P2_ATTR_LIFE_DURATION)
    if life is not None and life_type in (None, V1_LIFE_TYPE_SECONDS):
        ike["sa_lifetime_sec"] = life

    # PFS: a KE payload in Quick Mode (or a Group Description in the accepted
    # proposal) means a fresh D-H exchange for this CHILD SA. Absence of both,
    # on an observed QM negotiation, means PFS is off for this SA.
    ike["pfs_status"] = "enabled" if (has_ke or group) else "disabled"


def _analyse(messages: list[IkeMessage], ctx: dict) -> VPNSession:
    first = messages[0]
    icookie = first.initiator_spi
    rcookie = next(
        (m.responder_spi for m in messages if m.responder_spi != _ZERO_COOKIE), b"\x00" * 8
    )

    ike: dict = {"version": "IKEv1", "mode": "tunnel"}
    if ctx.get("ip_version"):
        ike["ip_version"] = ctx["ip_version"]
    nat = bool(ctx.get("nat_traversal", False))

    initial = _phase1_initial(messages)

    # --- Main vs Aggressive Mode -------------------------------------------
    if initial is not None:
        has_id = any(p.type == V1_PAYLOAD_ID for p in initial.payloads)
        ike["aggressive_mode"] = has_id or initial.exchange_type == EXCHANGE_V1_AGGRESSIVE
    else:
        # no SA-bearing message in the capture: trust the exchange-type byte
        ike["aggressive_mode"] = any(m.exchange_type == EXCHANGE_V1_AGGRESSIVE for m in messages)

    # --- phase-1 crypto parameters ---------------------------------------
    sa_msg = initial
    if sa_msg is None:
        # a Quick Mode SA payload uses phase-2 semantics; never read it as phase 1
        sa_msg = next(
            (
                m
                for m in messages
                if m.exchange_type != EXCHANGE_V1_QUICK
                and any(p.type == V1_PAYLOAD_SA for p in m.payloads)
            ),
            None,
        )
    if sa_msg is not None:
        sa = next(p for p in sa_msg.payloads if p.type == V1_PAYLOAD_SA)
        try:
            _apply_phase1_sa(ike, _first_transform(sa.raw)[2])
        except (WireFormatError, IndexError, struct.error):
            pass

    # --- phase-2 (Quick Mode): PFS + IPsec SA cipher --------------------
    qm_sa, qm_has_ke = _quick_mode_sa(messages)
    if qm_sa is not None:
        try:
            _apply_quick_mode(ike, qm_sa.raw, qm_has_ke)
        except (WireFormatError, IndexError, struct.error):
            pass
    ike.setdefault("pfs_status", "unknown")  # no Quick Mode observed -> undecidable

    # --- NAT-D -> NAT traversal -------------------------------------------
    for m in messages:
        if any(p.type in (V1_PAYLOAD_NAT_D, V1_PAYLOAD_NAT_D_DRAFT) for p in m.payloads):
            nat = True
    ike["nat_traversal"] = nat

    ike["capture_complete"] = initial is not None
    apply_edge_cases(ike, messages, ctx)  # P2-T4: VID vendor, IKE fragmentation, anti-replay

    return VPNSession(
        session_id=f"{icookie.hex()}-{rcookie.hex()}",
        initiator_ip=ctx.get("initiator_ip") or "",
        responder_ip=ctx.get("responder_ip") or "",
        ike=IkeParams(**ike),
    )


# --------------------------------------------------------------------------- #
# public API                                                                   #
# --------------------------------------------------------------------------- #
def _bucket_v1(messages: list[IkeMessage]) -> dict[bytes, list[IkeMessage]]:
    sas: dict[bytes, list[IkeMessage]] = {}
    for m in messages:
        sas.setdefault(m.initiator_spi, []).append(m)
    return sas


def parse_ikev1_sessions(source) -> list[VPNSession]:
    """Every IKEv1 phase-1 SA found in ``source``."""
    messages, ctx = _normalise(source)
    messages = [m for m in messages if m.is_ikev1]
    if not messages:
        return []
    return [_analyse(msgs, ctx) for msgs in _bucket_v1(messages).values()]


def parse_ikev1(source) -> VPNSession:
    """The primary IKEv1 phase-1 SA in ``source``.

    Raises :class:`NoIKEv1Error` when the source contains no IKEv1 message.
    """
    sessions = parse_ikev1_sessions(source)
    if not sessions:
        raise NoIKEv1Error("no IKEv1 messages in source")
    return sessions[0]


def exchange_mode_name(session: VPNSession) -> str:
    """Human label for the phase-1 exchange ("Main Mode" / "Aggressive Mode")."""
    key = EXCHANGE_V1_AGGRESSIVE if session.ike.aggressive_mode else EXCHANGE_V1_IDENTITY_PROTECT
    return EXCHANGE_V1_NAMES[key]
