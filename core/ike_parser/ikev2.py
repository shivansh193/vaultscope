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
import struct
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
from ._wire import IkeMessage, Proposal, WireFormatError, decode_message

_ZERO_SPI = b"\x00" * 8
_NON_ESP_MARKER = b"\x00\x00\x00\x00"


class NoIKEv2Error(ValueError):
    """No IKEv2 messages were found in the source."""


# --------------------------------------------------------------------------- #
# pcap ingestion                                                               #
# --------------------------------------------------------------------------- #
class _PcapMessage:
    __slots__ = ("msg", "ip_version", "src_ip", "dst_ip", "udp_port", "time", "frame")

    def __init__(self, msg, ip_version, src_ip, dst_ip, udp_port, time=0.0, frame=0):
        self.msg = msg
        self.ip_version = ip_version
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.udp_port = udp_port
        self.time = time
        self.frame = frame  # 1-based frame number in the source pcap


def _read_pcap(path: str | os.PathLike) -> tuple[list[_PcapMessage], list[tuple[int, int]]]:
    """Return (ike_messages, esp_records). Non-IKE / malformed frames are
    skipped; both IKEv1 and IKEv2 messages are kept (callers filter by version).
    ``esp_records`` is ``[(spi, seq), ...]`` for every ESP/AH packet -- used to
    anchor a mid-session capture and to spot anti-replay being off.
    """
    from scapy.layers.inet import IP, UDP  # noqa: PLC0415  (lazy: keep import light)
    from scapy.layers.inet6 import IPv6  # noqa: PLC0415
    from scapy.utils import rdpcap  # noqa: PLC0415

    try:
        from scapy.layers.ipsec import ESP  # noqa: PLC0415
    except Exception:  # pragma: no cover - older scapy
        ESP = None  # type: ignore[assignment]

    out: list[_PcapMessage] = []
    esp_records: list[tuple[int, int]] = []  # (spi, seq) for the anti-replay check

    def _record_esp(blob: bytes) -> None:
        if len(blob) >= 8:
            spi, seq = struct.unpack_from(">II", blob)
            esp_records.append((spi, seq))

    for _frame_i, pkt in enumerate(rdpcap(str(path)), start=1):
        if IP in pkt:
            ipv, ip_layer = "IPv4", pkt[IP]
        elif IPv6 in pkt:
            ipv, ip_layer = "IPv6", pkt[IPv6]
        else:
            continue

        if ESP is not None and ESP in pkt:
            _record_esp(struct.pack(">II", int(pkt[ESP].spi), int(pkt[ESP].seq)))
            continue
        if IPv6 not in pkt and IP in pkt and pkt[IP].proto in (50, 51):
            _record_esp(bytes(pkt[IP].payload))
            continue

        if UDP not in pkt:
            continue
        udp = pkt[UDP]
        if udp.sport not in (500, 4500) and udp.dport not in (500, 4500):
            continue

        # Use the bytes as captured. scapy binds UDP/500 + UDP/4500 to its
        # ISAKMP dissector, so bytes(udp.payload) would round-trip through that
        # (IKEv1-oriented) layer and can mangle an IKEv2 message; `.original`
        # is the untouched on-wire payload.
        inner = udp.payload
        payload = getattr(inner, "original", None) or bytes(inner)
        if not payload:
            continue

        on_4500 = 4500 in (udp.sport, udp.dport)
        if on_4500:
            if payload[:4] == _NON_ESP_MARKER:
                ike_bytes = payload[4:]
            else:
                _record_esp(payload)  # ESP-in-UDP data / keepalive
                continue
        else:
            ike_bytes = payload

        try:
            msg = decode_message(ike_bytes)
        except (WireFormatError, struct.error):
            continue
        if not (msg.is_ikev2 or msg.is_ikev1):
            continue

        out.append(
            _PcapMessage(
                msg,
                ipv,
                getattr(ip_layer, "src", None),
                getattr(ip_layer, "dst", None),
                4500 if on_4500 else 500,
                float(getattr(pkt, "time", 0.0)),
                _frame_i,
            )
        )
    return out, esp_records


# --------------------------------------------------------------------------- #
# source normalisation                                                         #
# --------------------------------------------------------------------------- #
def _normalise(source) -> tuple[list[IkeMessage], dict]:
    """Return (all IKE messages in capture order, context dict).

    Both IKEv1 and IKEv2 messages are returned; ``parse_ikevN`` filters by
    version. Kept in ``ikev2`` for history; ``ikev1`` imports it.
    """
    ctx: dict = {
        "ip_version": None,
        "initiator_ip": None,
        "responder_ip": None,
        "saw_esp": False,
        "esp_records": [],
    }

    if isinstance(source, str | os.PathLike):
        pmsgs, esp_records = _read_pcap(source)
        ctx["saw_esp"] = bool(esp_records)
        ctx["esp_records"] = esp_records
        # (key, timestamp) per IKE packet -- identical keys spaced apart are
        # retransmissions (secondary vendor fingerprint).
        ctx["ike_times"] = [
            ((p.msg.exchange_type, p.msg.message_id, p.msg.is_response), p.time) for p in pmsgs
        ]
        # (initiator_spi hex, pcap frame number) -- anomaly evidence pointers
        ctx["ike_frames"] = [(p.msg.initiator_spi.hex(), p.frame) for p in pmsgs]
        if pmsgs:
            ctx["ip_version"] = pmsgs[0].ip_version
            ctx["nat_traversal"] = any(p.udp_port == 4500 for p in pmsgs)
        return [p.msg for p in pmsgs], _fill_ip_ctx(ctx, pmsgs)

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
    return messages, ctx


def _fill_ip_ctx(ctx: dict, pmsgs: list[_PcapMessage]) -> dict:
    # first non-response message with message_id 0 = the initiator's opening
    # message (IKEv2 SA_INIT request, or IKEv1 MM/AM message 1). IKEv1 has no
    # response flag, so the earliest capture-order match is the initiator's.
    for p in pmsgs:
        if not p.msg.is_response and p.msg.message_id == 0:
            ctx["initiator_ip"] = p.src_ip
            ctx["responder_ip"] = p.dst_ip
            return ctx
    if pmsgs:
        ctx["initiator_ip"] = pmsgs[0].src_ip
        ctx["responder_ip"] = pmsgs[0].dst_ip
    return ctx


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
    if replay is False:
        ike["anti_replay"] = False

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
    ike: dict = {"version": "IKEv2", "mode": "tunnel", "aggressive_mode": False}
    if ctx.get("ip_version"):
        ike["ip_version"] = ctx["ip_version"]
    ike["nat_traversal"] = bool(ctx.get("nat_traversal", False))

    saw_sa_init = False
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

    return VPNSession(
        session_id=f"{init_spi.hex()}-{resp_spi.hex()}",
        initiator_ip=ctx.get("initiator_ip") or "",
        responder_ip=ctx.get("responder_ip") or "",
        ike=IkeParams(**ike),
        packet_refs=_frames_for(ctx, init_spi),
        timestamp=_first_timestamp(ctx),
    )


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
    messages, ctx = _normalise(source)
    messages = [m for m in messages if m.is_ikev2]
    if not messages:
        if ctx.get("saw_esp"):
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
            if anti_replay_from_esp(ctx.get("esp_records") or []) is False:
                ike["anti_replay"] = False
            return [VPNSession(session_id="esp-only", ike=IkeParams(**ike))]
        return []
    return [_analyse(msgs, ctx) for msgs in _bucket(messages).values()]


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
