"""Stage 1 ingestion: capture -> per-session IKE + ESP packet streams.

One read of a pcap / pcapng (or a live NIC), bucketed into IKE security
associations keyed by ``(SPI_i, SPI_r)`` for IKEv2 / ``(cookie_i, cookie_r)``
for IKEv1, with the data-plane (ESP/AH) packets kept alongside. Stage 2 (IKE
parser) consumes ``RawSession.ike_messages``; Stage 3 (flow features) consumes
``RawSession.esp_records`` / the ESP pcap.

Library choice (spec Section 3.2): ``pyshark`` (structured tshark fields) is
tried first; ``scapy`` raw parsing is the always-available fallback. The scapy
path reuses ``core.ike_parser._wire`` so a byte the parser can decode is a byte
ingestion can bucket.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

from core.ike_parser._transforms import EXCHANGE_IKE_SA_INIT, IKE_VERSION_1
from core.ike_parser._wire import IkeMessage, WireFormatError, decode_message

_NON_ESP_MARKER = b"\x00\x00\x00\x00"
# fragment payload types -- IKEv2 SKF (RFC 7383) = 53, IKEv1 Cisco = 132
_FRAGMENT_PAYLOAD_TYPES = (53, 132)
_IKE_FILTER = "udp port 500 or udp port 4500"  # documented; used by the pyshark path


@dataclass
class RawSession:
    """One IKE SA and its data-plane packets, straight off the wire."""

    session_id: str
    ike_version: str  # "IKEv1" | "IKEv2"
    ike_messages: list[IkeMessage] = field(default_factory=list)
    esp_records: list[tuple[int, int]] = field(default_factory=list)  # (spi, seq)
    initiator_ip: str | None = None
    responder_ip: str | None = None
    ip_version: str | None = None
    udp_ports: set[int] = field(default_factory=set)

    # --- Stage-1 edge-case flags (spec P1-T6) --------------------------------
    @property
    def nat_traversal(self) -> bool:
        return 4500 in self.udp_ports

    @property
    def fragmented_ike(self) -> bool:
        return any(p.type in _FRAGMENT_PAYLOAD_TYPES for m in self.ike_messages for p in m.payloads)

    @property
    def capture_complete(self) -> bool:
        """True once the SA-establishing first exchange is in the capture."""
        for m in self.ike_messages:
            if m.message_id == 0 and m.exchange_type in (EXCHANGE_IKE_SA_INIT, 2, 4):
                return True
        return False

    @property
    def ike_packets(self) -> int:
        return len(self.ike_messages)

    @property
    def esp_packets(self) -> int:
        return len(self.esp_records)


@dataclass
class IngestResult:
    sessions: list[RawSession] = field(default_factory=list)
    esp_only_records: list[tuple[int, int]] = field(default_factory=list)
    reader: str = "scapy"  # which backend actually ran
    packets_seen: int = 0

    def summary(self) -> dict:
        return {
            "session_count": len(self.sessions),
            "reader": self.reader,
            "packets_seen": self.packets_seen,
            "ike_versions": sorted({s.ike_version for s in self.sessions}),
            "has_esp": any(s.esp_records for s in self.sessions) or bool(self.esp_only_records),
            "incomplete_sessions": [s.session_id for s in self.sessions if not s.capture_complete],
            "nat_traversal_sessions": [s.session_id for s in self.sessions if s.nat_traversal],
        }

    def to_vpn_sessions(self):
        """Run each bucket through the Stage 2 parser -> core.models.VPNSession.

        A single pcap read for Stages 1+2, versus the parser re-reading the file.
        """
        from core.ike_parser import parse_ikev1_sessions, parse_ikev2_sessions

        out = []
        for s in self.sessions:
            parse = parse_ikev1_sessions if s.ike_version == "IKEv1" else parse_ikev2_sessions
            out.extend(parse(s.ike_messages))
        return out


# --------------------------------------------------------------------------- #
# bucketing                                                                    #
# --------------------------------------------------------------------------- #
def _session_key(msg: IkeMessage) -> bytes:
    """IKE SA identity. The initiator SPI/cookie is stable for the life of the
    SA; the responder half is 0 only in the very first request."""
    return msg.initiator_spi


def _bucket(
    records: Iterable[tuple[IkeMessage, str | None, str | None, str | None, int]],
) -> list[RawSession]:
    sessions: dict[bytes, RawSession] = {}
    for msg, src, dst, ipv, port in records:
        key = _session_key(msg)
        s = sessions.get(key)
        if s is None:
            s = RawSession(
                session_id="",
                ike_version="IKEv1" if msg.version == IKE_VERSION_1 else "IKEv2",
                ip_version=ipv,
            )
            sessions[key] = s
        s.ike_messages.append(msg)
        s.udp_ports.add(port)
        if src and s.initiator_ip is None and not msg.is_response and msg.message_id == 0:
            s.initiator_ip, s.responder_ip = src, dst

    for key, s in sessions.items():  # finalise ids once every message is known
        resp_spi = next(
            (m.responder_spi for m in s.ike_messages if m.responder_spi != b"\x00" * 8),
            b"\x00" * 8,
        )
        s.session_id = f"{key.hex()}-{resp_spi.hex()}"
    return list(sessions.values())


# --------------------------------------------------------------------------- #
# scapy backend                                                                #
# --------------------------------------------------------------------------- #
def _ingest_scapy(path: str | os.PathLike) -> IngestResult:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import rdpcap

    try:
        from scapy.layers.ipsec import ESP
    except Exception:  # pragma: no cover
        ESP = None  # type: ignore[assignment]

    ike_records: list[tuple[IkeMessage, str | None, str | None, str | None, int]] = []
    esp_by_key: dict[bytes | None, list[tuple[int, int]]] = {}
    seen = 0

    def _esp(blob: bytes, key: bytes | None) -> None:
        if len(blob) >= 8:
            esp_by_key.setdefault(key, []).append(struct.unpack_from(">II", blob))

    for pkt in rdpcap(str(path)):
        seen += 1
        if IP in pkt:
            ip, ipv = pkt[IP], "IPv4"
            src, dst, proto = ip.src, ip.dst, ip.proto
        elif IPv6 in pkt:
            ip, ipv = pkt[IPv6], "IPv6"
            src, dst, proto = ip.src, ip.dst, ip.nh
        else:
            continue

        if (ESP is not None and ESP in pkt) or proto in (50, 51):
            body = (
                struct.pack(">II", int(pkt[ESP].spi), int(pkt[ESP].seq))
                if (ESP is not None and ESP in pkt)
                else bytes(ip.payload)
            )
            _esp(body, None)
            continue

        if UDP not in pkt:
            continue
        udp = pkt[UDP]
        if udp.sport not in (500, 4500) and udp.dport not in (500, 4500):
            continue
        payload = getattr(udp.payload, "original", None) or bytes(udp.payload)
        if not payload:
            continue

        on_4500 = 4500 in (udp.sport, udp.dport)
        if on_4500 and payload[:4] != _NON_ESP_MARKER:
            _esp(payload, None)
            continue
        ike_bytes = payload[4:] if on_4500 else payload
        try:
            msg = decode_message(ike_bytes)
        except (WireFormatError, struct.error):
            continue
        if not (msg.is_ikev2 or msg.is_ikev1):
            continue
        ike_records.append((msg, src, dst, ipv, 4500 if on_4500 else 500))

    sessions = _bucket(ike_records)
    # attach ESP: single session -> all its packets; otherwise leave unattached
    all_esp = [rec for recs in esp_by_key.values() for rec in recs]
    if len(sessions) == 1 and all_esp:
        sessions[0].esp_records.extend(all_esp)
        esp_only: list[tuple[int, int]] = []
    else:
        esp_only = all_esp
    return IngestResult(
        sessions=sessions, esp_only_records=esp_only, reader="scapy", packets_seen=seen
    )


# --------------------------------------------------------------------------- #
# pyshark backend (structured; optional)                                       #
# --------------------------------------------------------------------------- #
def _ingest_pyshark(path: str | os.PathLike) -> IngestResult:
    import pyshark  # noqa: PLC0415

    cap = pyshark.FileCapture(
        str(path), display_filter="isakmp or esp or ah", keep_packets=False, use_json=False
    )
    ike_records = []
    esp_records: list[tuple[int, int]] = []
    seen = 0
    try:
        for pkt in cap:
            seen += 1
            ipv = "IPv6" if "IPV6" in pkt else "IPv4"
            src = getattr(getattr(pkt, "ip", None), "src", None) or getattr(
                getattr(pkt, "ipv6", None), "src", None
            )
            dst = getattr(getattr(pkt, "ip", None), "dst", None) or getattr(
                getattr(pkt, "ipv6", None), "dst", None
            )
            if "ESP" in pkt or "AH" in pkt:
                layer = pkt["esp"] if "ESP" in pkt else pkt["ah"]
                spi = int(getattr(layer, "spi", "0x0"), 16) if hasattr(layer, "spi") else 0
                seq = int(getattr(layer, "sequence", 0))
                esp_records.append((spi, seq))
                continue
            if "ISAKMP" not in pkt:
                continue
            raw_hex = getattr(pkt["isakmp"], "isakmp_raw", None) or getattr(
                pkt["udp"], "payload", ""
            ).replace(":", "")
            try:
                msg = decode_message(bytes.fromhex(raw_hex))
            except (ValueError, WireFormatError, struct.error):
                continue
            if msg.is_ikev2 or msg.is_ikev1:
                port = 4500 if getattr(pkt["udp"], "dstport", "500") == "4500" else 500
                ike_records.append((msg, src, dst, ipv, port))
    finally:
        cap.close()

    sessions = _bucket(ike_records)
    if len(sessions) == 1 and esp_records:
        sessions[0].esp_records.extend(esp_records)
        esp_records = []
    return IngestResult(
        sessions=sessions, esp_only_records=esp_records, reader="pyshark", packets_seen=seen
    )


# --------------------------------------------------------------------------- #
# public entry point                                                           #
# --------------------------------------------------------------------------- #
def ingest(source: str | os.PathLike, *, prefer: str = "scapy") -> IngestResult:
    """Bucket a capture into per-session IKE + ESP streams.

    ``prefer="pyshark"`` tries the structured tshark reader first and falls
    back to scapy on any failure (missing tshark, dissector quirk). The default
    is ``"scapy"`` -- always available, and it shares the parser's decoder.
    """
    if prefer == "pyshark":
        try:
            return _ingest_pyshark(source)
        except Exception:  # tshark missing / dissection failure -> raw fallback
            pass
    return _ingest_scapy(source)
