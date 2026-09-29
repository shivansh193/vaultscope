"""One read of a capture file: every IKE message and every ESP/AH packet.

Stage 1 (bucketing), Stage 2 (the IKE parser) and Stage 3 (flow features) all
need the same packets from the same file. They used to walk it three times with
three slightly different readers -- and the one the pipeline actually ran
(ingestion) threw away the frame numbers, timestamps, IP version and UDP port
that the parser needs, so every analysed session came out with no evidence
pointers, no timestamp, IPv4 on an IPv6 capture and NAT-T off on UDP 4500.

This module is the only thing that turns pcap bytes into packets. Everything it
knows about a packet travels with it:

    read = read_capture("capture.pcap")
    read.ike   # [IkeFrame(msg, ip_version, src_ip, dst_ip, udp_port, time, frame)]
    read.esp   # [EspFrame(spi, seq, src_ip, dst_ip, time, size, frame)]

``frame`` is the 1-based frame number Wireshark shows, so any finding that
carries it can be checked by hand.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from core.ike_parser._wire import IkeMessage, WireFormatError, decode_message

# RFC 3948: on UDP 4500 an IKE message is prefixed with four zero bytes; any
# other first word is the SPI of an ESP packet riding the same port.
NON_ESP_MARKER = b"\x00\x00\x00\x00"
IKE_PORTS = (500, 4500)
PROTO_ESP, PROTO_AH = 50, 51


@dataclass(frozen=True, slots=True)
class IkeFrame:
    """One decoded IKE message and where it was seen."""

    msg: IkeMessage
    ip_version: str  # "IPv4" | "IPv6"
    src_ip: str
    dst_ip: str
    udp_port: int  # 500, or 4500 under NAT-T
    time: float  # epoch seconds
    frame: int  # 1-based frame number in the capture


@dataclass(frozen=True, slots=True)
class EspFrame:
    """One ESP/AH data-plane packet, reduced to metadata (the payload is ciphertext)."""

    spi: int | None
    seq: int | None
    src_ip: str
    dst_ip: str
    time: float
    size: int  # on-wire frame length -- what Stage 3 measures
    frame: int

    @property
    def peers(self) -> frozenset[str]:
        return frozenset({self.src_ip, self.dst_ip})


@dataclass
class CaptureRead:
    ike: list[IkeFrame] = field(default_factory=list)
    esp: list[EspFrame] = field(default_factory=list)
    packets_seen: int = 0
    first_time: float | None = None
    last_time: float | None = None

    @property
    def duration_sec(self) -> float:
        if self.first_time is None or self.last_time is None:
            return 0.0
        return max(0.0, self.last_time - self.first_time)


def _spi_seq(body: bytes, proto: int) -> tuple[int | None, int | None]:
    """ESP carries SPI+seq at offset 0; AH (RFC 4302) after a 4-byte preamble."""
    offset = 4 if proto == PROTO_AH else 0
    if len(body) < offset + 8:
        spi = struct.unpack_from(">I", body, offset)[0] if len(body) >= offset + 4 else None
        return spi, None
    return struct.unpack_from(">II", body, offset)


def read_capture(path: str | os.PathLike) -> CaptureRead:
    """Walk ``path`` (pcap or pcapng) once. Non-IPsec and malformed frames are skipped."""
    from scapy.layers.inet import IP, UDP  # noqa: PLC0415  (lazy: scapy is slow to import)
    from scapy.layers.inet6 import IPv6  # noqa: PLC0415
    from scapy.utils import PcapReader  # noqa: PLC0415

    read = CaptureRead()
    with PcapReader(str(path)) as reader:
        for frame, pkt in enumerate(reader, start=1):
            read.packets_seen = frame
            t = float(getattr(pkt, "time", 0.0))
            if read.first_time is None:
                read.first_time = t
            read.last_time = t

            if IP in pkt:
                ip, ipv, proto = pkt[IP], "IPv4", pkt[IP].proto
            elif IPv6 in pkt:
                ip, ipv, proto = pkt[IPv6], "IPv6", pkt[IPv6].nh
            else:
                continue
            src, dst = str(ip.src), str(ip.dst)

            if proto in (PROTO_ESP, PROTO_AH):
                body = bytes(ip.payload)
                spi, seq = _spi_seq(body, proto)
                read.esp.append(EspFrame(spi, seq, src, dst, t, len(pkt), frame))
                continue

            if UDP not in pkt:
                continue
            udp = pkt[UDP]
            if udp.sport not in IKE_PORTS and udp.dport not in IKE_PORTS:
                continue
            # The bytes as captured: scapy binds UDP/500 and /4500 to its IKEv1
            # ISAKMP dissector, and round-tripping an IKEv2 message through
            # that layer can mangle it. `.original` is the untouched payload.
            payload = getattr(udp.payload, "original", None) or bytes(udp.payload)
            if not payload:
                continue

            on_4500 = 4500 in (udp.sport, udp.dport)
            if on_4500 and payload[:4] != NON_ESP_MARKER:
                if len(payload) >= 8:  # a 1-byte NAT keepalive is not ESP
                    spi, seq = _spi_seq(payload, PROTO_ESP)
                    read.esp.append(EspFrame(spi, seq, src, dst, t, len(pkt), frame))
                continue

            try:
                msg = decode_message(payload[4:] if on_4500 else payload)
            except (WireFormatError, struct.error):
                continue
            if msg.is_ikev2 or msg.is_ikev1:
                read.ike.append(IkeFrame(msg, ipv, src, dst, 4500 if on_4500 else 500, t, frame))
    return read
