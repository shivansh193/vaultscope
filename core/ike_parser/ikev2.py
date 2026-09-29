"""Stage 2 - IKEv2 handshake reconstruction (P2-T1).

``parse_ikev2(source)`` fills the ``ike`` block of a canonical
:class:`core.models.VPNSession`:

    >>> parse_ikev2("capture.pcap").ike.encryption
    'AES-256-GCM'

``source`` may be

  * a path to a pcap / pcapng file (``str`` or ``os.PathLike``),
  * raw bytes of a single IKE message,
  * an iterable of raw IKE message ``bytes``,
  * an iterable of pre-decoded :class:`._wire.IkeMessage`.

What it extracts (spec Section 4, "IKEv2 Message Handling"):

  IKE_SA_INIT      accepted ENCR / PRF / INTEG / D-H transforms, KE group,
                   NAT-detection + fragmentation notifies
  IKE_AUTH         AUTH method (or EAP), USE_TRANSPORT_MODE -> transport mode,
                   the initial CHILD_SA proposal
  CREATE_CHILD_SA  KE payload -> PFS enabled; child rekey vs IKE rekey

PFS: ``enabled`` if any observed CHILD_SA negotiation carries a KE payload or a
non-NONE D-H transform; ``disabled`` if a CHILD_SA negotiation is seen without
one; ``unknown`` if no CHILD_SA negotiation is observed at all (mid-session
capture) -- never guessed, so rule R10 does not misfire.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from collections.abc import Iterable

from core.models import IkeParams, VPNSession

from ._transforms import (
    EXCHANGE_CREATE_CHILD_SA,
    EXCHANGE_IKE_AUTH,
    EXCHANGE_IKE_SA_INIT,
    NOTIFY_NAT_DETECTION_DESTINATION_IP,
    NOTIFY_NAT_DETECTION_SOURCE_IP,
    NOTIFY_USE_TRANSPORT_MODE,
    PAYLOAD_AUTH,
    PAYLOAD_EAP,
    PAYLOAD_KE,
    PAYLOAD_NOTIFY,
    PAYLOAD_SA,
    PAYLOAD_SKF,
    PAYLOAD_VENDOR_ID,
    PROTOCOL_AH,
    PROTOCOL_ESP,
    TRANSFORM_TYPE_DH,
    TRANSFORM_TYPE_ENCR,
    TRANSFORM_TYPE_INTEG,
    TRANSFORM_TYPE_PRF,
    canon_auth_method,
    canon_dh_group,
    canon_encryption,
    canon_integrity,
    canon_prf,
    is_aead_encr,
)
from ._vendor_ids import fingerprint_vendor
from ._wire import IkeMessage, Proposal, decode_message

_ZERO_SPI = b"\x00" * 8


class NoIKEv2Error(ValueError):
    """No IKEv2 messages were found in the source."""


# --------------------------------------------------------------------------- #
# source normalisation                                                         #
# --------------------------------------------------------------------------- #
def _frames_ctx(frames, esp_records: list[tuple[int, int]]) -> dict:
    """Context for one IKE SA from its captured frames (``core.capture.IkeFrame``).

    Everything here is per SA: a capture holding six tunnels has six initiator
    addresses, six first-seen times and six sets of evidence frames.
    """
    ctx: dict = {
        "ip_version": frames[0].ip_version if frames else None,
        "initiator_ip": None,
        "responder_ip": None,
        "saw_esp": bool(esp_records),
        "esp_records": esp_records,
        # (key, timestamp) per IKE packet -- identical keys spaced apart are
        # retransmissions (secondary vendor fingerprint).
        "ike_times": [
            ((f.msg.exchange_type, f.msg.message_id, f.msg.is_response), f.time) for f in frames
        ],
        # (initiator_spi hex, pcap frame number) -- anomaly evidence pointers
        "ike_frames": [(f.msg.initiator_spi.hex(), f.frame) for f in frames],
        "nat_traversal": any(f.udp_port == 4500 for f in frames),
    }
    # first non-response message with message_id 0 = the initiator's opening
    # message (IKEv2 SA_INIT request, or IKEv1 MM/AM message 1). IKEv1 has no
    # response flag, so the earliest capture-order match is the initiator's.
    opener = next((f for f in frames if not f.msg.is_response and f.msg.message_id == 0), None)
    opener = opener or (frames[0] if frames else None)
    if opener is not None:
        ctx["initiator_ip"], ctx["responder_ip"] = opener.src_ip, opener.dst_ip
    return ctx


def _groups(source) -> list[tuple[list[IkeMessage], dict]]:
    """``source`` -> ``[(messages, ctx), ...]``, one group per IKE SA where the
    source carries packet metadata (a capture path, or a Stage 1
    ``RawSession``), else a single group of bare messages.
    """
    if hasattr(source, "ike_frames"):  # a Stage 1 RawSession: already one SA
        frames = list(source.ike_frames)
        return [([f.msg for f in frames], _frames_ctx(frames, list(source.esp_records)))]

    if isinstance(source, str | os.PathLike):
        from core.capture import read_capture  # noqa: PLC0415  (core.capture imports _wire)

        read = read_capture(source)
        by_sa: OrderedDict[bytes, list] = OrderedDict()
        for f in read.ike:
            by_sa.setdefault(f.msg.initiator_spi, []).append(f)
        esp = [(e.spi or 0, e.seq or 0) for e in read.esp]
        if not by_sa:
            return [([], _frames_ctx([], esp))] if esp else [([], {})]
        from core.ingestion.engine import nat_owner  # noqa: PLC0415

        pairs: dict[frozenset[str], list] = {}
        for key, frames in by_sa.items():
            pairs.setdefault(frozenset({frames[0].src_ip, frames[0].dst_ip}), []).append(key)
        owned: dict[bytes, list[tuple[int, int]]] = {key: [] for key in by_sa}
        for e in read.esp:  # same attribution as Stage 1, NAT included
            for key in pairs.get(e.peers) or nat_owner(e.peers, pairs):
                owned[key].append((e.spi or 0, e.seq or 0))
        groups = []
        for key, frames in by_sa.items():
            mine = owned[key]
            groups.append(([f.msg for f in frames], _frames_ctx(frames, mine)))
        return groups

    if isinstance(source, bytes | bytearray):
        source = [bytes(source)]
    messages: list[IkeMessage] = []
    for item in source:  # type: ignore[assignment]
        if isinstance(item, IkeMessage):
            msg = item
        elif isinstance(item, bytes | bytearray):
            msg = decode_message(bytes(item))
        else:
            raise TypeError(f"unsupported IKE source element: {type(item)!r}")
        if msg.is_ikev2 or msg.is_ikev1:
            messages.append(msg)
    return [(messages, {})]


def _normalise(source) -> tuple[list[IkeMessage], dict]:
    """All IKE messages in ``source`` (v1 + v2, capture order) and the first SA's context."""
    groups = _groups(source)
    return [m for messages, _ in groups for m in messages], groups[0][1]


# --------------------------------------------------------------------------- #
# analysis                                                                     #
# --------------------------------------------------------------------------- #
def _apply_ike_proposal(ike: dict, prop: Proposal) -> None:
    """Write the accepted ENCR/INTEG/PRF/D-H transforms into the ``ike`` accumulator."""
    encr = prop.first(TRANSFORM_TYPE_ENCR)
    integ = prop.first(TRANSFORM_TYPE_INTEG)
    prf = prop.first(TRANSFORM_TYPE_PRF)
    dh = prop.first(TRANSFORM_TYPE_DH)

    aead = encr is not None and is_aead_encr(encr.id)
    if encr is not None:
        ike["encryption"] = canon_encryption(encr.id, encr.key_length)
    integ_str = canon_integrity(integ.id if integ is not None else None, aead=aead)
    if integ_str is not None:
        ike["integrity"] = integ_str
    if prf is not None:
        ike["prf"] = canon_prf(prf.id)
    if dh is not None and dh.id != 0:
        ike["dh_group"] = canon_dh_group(dh.id)


def _notify_types(msg: IkeMessage) -> list[int]:
    return [
        p.notify_type
        for p in msg.all_payloads()
        if p.type == PAYLOAD_NOTIFY and p.notify_type is not None
    ]


# fragment payload types: IKEv2 SKF (RFC 7383) = 53, IKEv1 Cisco = 132
_FRAGMENT_PAYLOAD_TYPES = (PAYLOAD_SKF, 132)
# Vendor ID payload: 43 in IKEv2, 13 in IKEv1/ISAKMP
_VENDOR_ID_PAYLOAD_TYPES = (PAYLOAD_VENDOR_ID, 13)


def anti_replay_from_esp(esp_records: list[tuple[int, int]]) -> bool | None:
    """False when a captured ESP SA never advances its sequence number
    (anti-replay effectively off, RFC 4303 3.4.3); None when undecidable.
    Shared by the IKEv1 and IKEv2 analysers."""
    by_spi: dict[int, list[int]] = {}
    for spi, seq in esp_records:
        by_spi.setdefault(spi, []).append(seq)
    decided: bool | None = None
    for seqs in by_spi.values():
        if len(seqs) >= 4:
            if len(set(seqs)) == 1:  # every packet reuses one sequence number
                return False
            decided = True  # this SA does advance -> anti-replay is on
    return decided


def apply_edge_cases(ike: dict, messages: list[IkeMessage], ctx: dict) -> None:
    """P2-T4 + extended signals: Vendor ID fingerprint, IKE fragmentation,
    ESP anti-replay, Dead Peer Detection, retransmission timing, peer cert."""
    vids = [
        p.raw.hex()
        for m in messages
        for p in m.all_payloads()
        if p.type in _VENDOR_ID_PAYLOAD_TYPES
    ]
    vendor = fingerprint_vendor(vids)
    if vendor != "unknown":
        ike["vendor"] = vendor

    if any(p.type in _FRAGMENT_PAYLOAD_TYPES for m in messages for p in m.payloads):
        ike["fragmented_ike"] = True

    replay = anti_replay_from_esp(ctx.get("esp_records") or [])
    if replay is not None:
        ike["anti_replay"] = replay

    from ._signals import cert_from_messages, dpd_from_messages, retransmit_interval_ms

    dpd_status, dpd_interval = dpd_from_messages(messages)
    if dpd_status != "unknown":
        ike["dpd_status"] = dpd_status
        if dpd_interval is not None:
            ike["dpd_interval_sec"] = dpd_interval
    elif ike.get("capture_complete") and ike.get("version") == "IKEv1":
        # a complete IKEv1 handshake that never announced the DPD VID
        ike["dpd_status"] = "disabled"

    rtx = retransmit_interval_ms(ctx.get("ike_times"))
    if rtx is not None:
        ike["retransmit_interval_ms"] = rtx

    cert = cert_from_messages(messages)
    if cert is not None:
        ike["cert"] = cert


def _child_sa_payload(msg: IkeMessage):
    for p in msg.all_payloads():
        if (
            p.type == PAYLOAD_SA
            and p.proposals
            and p.proposals[0].protocol_id
            in (
                PROTOCOL_ESP,
                PROTOCOL_AH,
            )
        ):
            return p
    return None


def _analyse(messages: list[IkeMessage], ctx: dict) -> VPNSession:
    init_spi = messages[0].initiator_spi
    resp_spi = next((m.responder_spi for m in messages if m.responder_spi != _ZERO_SPI), _ZERO_SPI)

    # Accumulate only what is actually observed; unset crypto fields fall to the
    # core.models.IkeParams defaults (a known gap when capture_complete is False).
    ike: dict = {"version": "IKEv2", "aggressive_mode": False}
    if ctx.get("ip_version"):
        ike["ip_version"] = ctx["ip_version"]
    ike["nat_traversal"] = bool(ctx.get("nat_traversal", False))

    saw_sa_init = False
    saw_readable_auth = False  # IKE_AUTH decoded in the clear (key-logged capture)
    saw_sa_init_response = False
    proposal_applied_from_response = False
    child_negotiations: list[dict] = []

    for msg in messages:
        et = msg.exchange_type
        notifies = set(_notify_types(msg))

        if et == EXCHANGE_IKE_SA_INIT:
            saw_sa_init = True
            sa = msg.first(PAYLOAD_SA)
            if sa is not None and sa.proposals:
                if msg.is_response:
                    _apply_ike_proposal(ike, sa.proposals[0])
                    proposal_applied_from_response = True
                    saw_sa_init_response = True
                elif not proposal_applied_from_response:
                    _apply_ike_proposal(ike, sa.proposals[0])
            ke = msg.first(PAYLOAD_KE)
            if ke is not None and ke.dh_group is not None and "dh_group" not in ike:
                ike["dh_group"] = canon_dh_group(ke.dh_group)
            if notifies & {NOTIFY_NAT_DETECTION_SOURCE_IP, NOTIFY_NAT_DETECTION_DESTINATION_IP}:
                # capability signal; real NAT is confirmed by the port-4500 switch
                ike["nat_traversal"] = ike["nat_traversal"] or bool(ctx.get("nat_traversal", False))

        elif et == EXCHANGE_IKE_AUTH:
            auth = msg.first(PAYLOAD_AUTH)
            eap = bool(msg.find(PAYLOAD_EAP))
            if auth is not None or eap:
                am = canon_auth_method(auth.auth_method if auth is not None else None, eap=eap)
                if am is not None:
                    ike["auth_method"] = am
            if NOTIFY_USE_TRANSPORT_MODE in notifies:
                ike["mode"] = "transport"
            child = _child_sa_payload(msg)
            saw_readable_auth = saw_readable_auth or auth is not None or eap or child is not None
            if child is not None:
                child_negotiations.append(
                    {
                        "source": "ike_auth",
                        "has_ke": any(p.type == PAYLOAD_KE for p in msg.all_payloads()),
                        "dh_ok": child.proposals[0].has_dh(),
                    }
                )

        elif et == EXCHANGE_CREATE_CHILD_SA:
            child = _child_sa_payload(msg)
            if child is not None:  # ignore IKE-SA rekeys (proposal protocol_id == IKE)
                child_negotiations.append(
                    {
                        "source": "create_child_sa",
                        "has_ke": any(p.type == PAYLOAD_KE for p in msg.all_payloads()),
                        "dh_ok": child.proposals[0].has_dh(),
                    }
                )

    # Mode rides in IKE_AUTH (USE_TRANSPORT_MODE, RFC 7296 s1.3.1), which is
    # encrypted unless the capture was key-logged. Tunnel is only a finding when
    # a readable IKE_AUTH lacked the notify; otherwise the mode was not seen.
    if "mode" not in ike:
        ike["mode"] = "tunnel" if saw_readable_auth else "unknown"

    capture_complete = saw_sa_init_response or (saw_sa_init and "encryption" in ike)
    ike["capture_complete"] = capture_complete
    apply_edge_cases(ike, messages, ctx)

    # PFS resolution -- conservative, mirrors spec Section 4 ("CREATE_CHILD_SA:
    # detect KE payload -> PFS enabled; absence of KE -> PFS disabled") and the
    # Section 12 warning against a false "disabled" on incomplete captures:
    #   enabled  : any child negotiation carried a KE payload or a non-NONE D-H
    #              transform in its accepted proposal
    #   disabled : an actual CREATE_CHILD_SA (re)key was seen without either, OR
    #              a complete capture's IKE_AUTH child SA proposal had no D-H
    #   unknown  : no child negotiation seen, or only an incomplete IKE_AUTH one
    if any(c["has_ke"] or c["dh_ok"] for c in child_negotiations):
        ike["pfs_status"] = "enabled"
    elif any(c["source"] == "create_child_sa" for c in child_negotiations):
        ike["pfs_status"] = "disabled"
    elif capture_complete and any(c["source"] == "ike_auth" for c in child_negotiations):
        ike["pfs_status"] = "disabled"
    else:
        ike["pfs_status"] = "unknown"

    ike["msg_sizes"] = [m.length or 0 for m in messages]
    mark_unobserved(ike)
    return VPNSession(
        session_id=f"{init_spi.hex()}-{resp_spi.hex()}",
        initiator_ip=ctx.get("initiator_ip") or "",
        responder_ip=ctx.get("responder_ip") or "",
        ike=IkeParams(**ike),
        packet_refs=_frames_for(ctx, init_spi),
        timestamp=_first_timestamp(ctx),
    )


def mark_unobserved(ike: dict) -> None:
    """A field the capture never revealed is ``unknown``, never the model default.

    ``IkeParams`` defaults describe a strong suite (AES-256-GCM, ECP256, RSA).
    Letting them stand in for a field the handshake never showed would report
    a truncated capture of a DES tunnel as SAFE -- a false negative, which for
    an assessment tool is the worse failure. Rules never fire on ``unknown``.
    """
    for key in ("encryption", "integrity", "prf", "dh_group"):
        ike.setdefault(key, "unknown")
    ike.setdefault("auth_method", None)


def _frames_for(ctx: dict, init_spi: bytes) -> list[int]:
    key = init_spi.hex()
    return [f for spi_hex, f in ctx.get("ike_frames", []) if spi_hex == key]


def _first_timestamp(ctx: dict) -> str:
    times = [t for _k, t in ctx.get("ike_times", []) if t]
    if not times:
        return ""
    import datetime as _dt

    return _dt.datetime.fromtimestamp(min(times), tz=_dt.UTC).isoformat()


# --------------------------------------------------------------------------- #
# public API                                                                   #
# --------------------------------------------------------------------------- #
def _bucket(messages: list[IkeMessage]) -> OrderedDict[bytes, list[IkeMessage]]:
    """Group IKEv2 messages into IKE SAs, keyed by the initiator SPI."""
    sas: OrderedDict[bytes, list[IkeMessage]] = OrderedDict()
    for msg in messages:
        sas.setdefault(msg.initiator_spi, []).append(msg)
    return sas


def parse_ikev2_sessions(source) -> list[VPNSession]:
    """Every IKEv2 SA found in ``source`` (see module docstring for types)."""
    sessions: list[VPNSession] = []
    for messages, ctx in _groups(source):
        v2 = [m for m in messages if m.is_ikev2]
        if v2:
            sessions.extend(_analyse(msgs, ctx) for msgs in _bucket(v2).values())
        elif not messages and ctx.get("saw_esp"):
            sessions.append(_esp_only(ctx))
    return sessions


def _esp_only(ctx: dict) -> VPNSession:
    """A mid-session capture: ESP seen, no handshake. Nothing is guessed."""
    ike = dict(
        version="IKEv2",
        pfs_status="unknown",
        capture_complete=False,
        auth_method=None,
        encryption="unknown",
        integrity="unknown",
        prf="unknown",
        dh_group="unknown",
    )
    if ctx.get("ip_version"):
        ike["ip_version"] = ctx["ip_version"]
    replay = anti_replay_from_esp(ctx.get("esp_records") or [])
    if replay is not None:
        ike["anti_replay"] = replay
    return VPNSession(session_id="esp-only", ike=IkeParams(**ike))


def parse_ikev2(source) -> VPNSession:
    """The primary IKEv2 SA in ``source``.

    Raises :class:`NoIKEv2Error` only when the source has neither an IKEv2
    message nor any ESP packet to anchor a mid-session record.
    """
    sessions = parse_ikev2_sessions(source)
    if not sessions:
        raise NoIKEv2Error("no IKEv2 messages or ESP packets in source")
    return sessions[0]


def iter_ike_messages(source) -> Iterable[IkeMessage]:
    """Low-level helper: every decoded IKE message (v1 + v2), in capture order."""
    messages, _ = _normalise(source)
    return messages
