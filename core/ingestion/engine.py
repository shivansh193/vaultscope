"""Stage 1 ingestion: capture -> per-session IKE + ESP packet streams.

One read of a pcap / pcapng (``core.capture.read_capture``), bucketed into IKE
security associations keyed by ``(SPI_i, SPI_r)`` for IKEv2 /
``(cookie_i, cookie_r)`` for IKEv1, with each SA's data-plane (ESP/AH) packets
kept alongside. Stage 2 parses a ``RawSession`` directly -- its frames carry
the frame numbers, timestamps, addresses and ports the parser needs -- and
Stage 3 reads the same ``EspFrame`` list, so nothing walks the file twice.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from core.capture import CaptureRead, EspFrame, IkeFrame, read_capture
from core.ike_parser._transforms import EXCHANGE_IKE_SA_INIT, IKE_VERSION_1

# fragment payload types -- IKEv2 SKF (RFC 7383) = 53, IKEv1 Cisco = 132
_FRAGMENT_PAYLOAD_TYPES = (53, 132)
_ZERO_SPI = b"\x00" * 8


@dataclass
class RawSession:
    """One IKE SA and its data-plane packets, straight off the wire."""

    session_id: str
    ike_version: str  # "IKEv1" | "IKEv2"
    ike_frames: list[IkeFrame] = field(default_factory=list)
    esp_frames: list[EspFrame] = field(default_factory=list)
    initiator_ip: str | None = None
    responder_ip: str | None = None
    ip_version: str | None = None

    @property
    def ike_messages(self):
        return [f.msg for f in self.ike_frames]

    @property
    def esp_records(self) -> list[tuple[int, int]]:
        """``(spi, seq)`` per ESP packet -- the parser's anti-replay input."""
        return [(e.spi or 0, e.seq or 0) for e in self.esp_frames]

    @property
    def peers(self) -> frozenset[str]:
        return frozenset({self.initiator_ip or "", self.responder_ip or ""}) - {""}

    @property
    def udp_ports(self) -> set[int]:
        return {f.udp_port for f in self.ike_frames}

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
        return any(
            m.message_id == 0 and m.exchange_type in (EXCHANGE_IKE_SA_INIT, 2, 4)
            for m in self.ike_messages
        )

    @property
    def ike_packets(self) -> int:
        return len(self.ike_frames)

    @property
    def esp_packets(self) -> int:
        return len(self.esp_frames)


@dataclass
class IngestResult:
    sessions: list[RawSession] = field(default_factory=list)
    # ESP whose peers set up no SA inside this capture -- a mid-session capture.
    orphan_esp: list[EspFrame] = field(default_factory=list)
    packets_seen: int = 0
    duration_sec: float = 0.0
    reader: str = "scapy"

    @property
    def esp_only_records(self) -> list[tuple[int, int]]:
        return [(e.spi or 0, e.seq or 0) for e in self.orphan_esp]

    def summary(self) -> dict:
        return {
            "session_count": len(self.sessions),
            "reader": self.reader,
            "packets_seen": self.packets_seen,
            "ike_versions": sorted({s.ike_version for s in self.sessions}),
            "has_esp": any(s.esp_frames for s in self.sessions) or bool(self.orphan_esp),
            "incomplete_sessions": [s.session_id for s in self.sessions if not s.capture_complete],
            "nat_traversal_sessions": [s.session_id for s in self.sessions if s.nat_traversal],
        }

    def to_vpn_sessions(self):
        """Run each bucket through the Stage 2 parser -> core.models.VPNSession."""
        from core.ike_parser import parse_ikev1_sessions, parse_ikev2_sessions

        out = []
        for s in self.sessions:
            parse = parse_ikev1_sessions if s.ike_version == "IKEv1" else parse_ikev2_sessions
            out.extend(parse(s))
        return out


def bucket(read: CaptureRead) -> IngestResult:
    """Group a capture's frames into IKE SAs and hand each SA its ESP packets."""
    by_sa: dict[bytes, RawSession] = {}
    for f in read.ike:
        # The initiator SPI/cookie is stable for the life of the SA; the
        # responder half is 0 only in the very first request.
        key = f.msg.initiator_spi
        s = by_sa.get(key)
        if s is None:
            s = by_sa[key] = RawSession(
                session_id="",
                ike_version="IKEv1" if f.msg.version == IKE_VERSION_1 else "IKEv2",
                ip_version=f.ip_version,
            )
        s.ike_frames.append(f)
        if s.initiator_ip is None and not f.msg.is_response and f.msg.message_id == 0:
            s.initiator_ip, s.responder_ip = f.src_ip, f.dst_ip

    sessions = list(by_sa.values())
    for key, s in by_sa.items():  # finalise once every message is known
        if s.initiator_ip is None:  # mid-session: no opener, take the first message
            s.initiator_ip, s.responder_ip = s.ike_frames[0].src_ip, s.ike_frames[0].dst_ip
        resp = next((m.responder_spi for m in s.ike_messages if m.responder_spi != _ZERO_SPI), None)
        s.session_id = f"{key.hex()}-{(resp or _ZERO_SPI).hex()}"

    # ESP SPIs are negotiated inside the encrypted exchange, so the peer pair
    # is the only link between a data-plane packet and the SA that set it up.
    # Several SAs between one pair share its ESP: each rekey is the same tunnel.
    by_pair: dict[frozenset[str], list[RawSession]] = {}
    for s in sessions:
        by_pair.setdefault(s.peers, []).append(s)
    orphans: list[EspFrame] = []
    for e in read.esp:
        owners = by_pair.get(e.peers) or nat_owner(e.peers, by_pair)
        for s in owners:
            s.esp_frames.append(e)
        if not owners:
            orphans.append(e)

    return IngestResult(
        sessions=sessions,
        orphan_esp=orphans,
        packets_seen=read.packets_seen,
        duration_sec=read.duration_sec,
    )


def nat_owner(peers: frozenset[str], by_pair: dict[frozenset[str], list]) -> list:
    """The SAs a NATed ESP packet belongs to, or ``[]``.

    NAT rewrites one side of the pair, so ESP that matches no SA exactly still
    shares an endpoint with its own. Attribute it only when exactly one peer
    pair shares an endpoint -- otherwise it is ambiguous and stays an orphan.
    """
    candidates = [pair for pair in by_pair if pair & peers]
    return by_pair[candidates[0]] if len(candidates) == 1 else []


def ingest(source: str | os.PathLike | CaptureRead) -> IngestResult:
    """Bucket a capture into per-session IKE + ESP streams."""
    return bucket(source if isinstance(source, CaptureRead) else read_capture(source))
