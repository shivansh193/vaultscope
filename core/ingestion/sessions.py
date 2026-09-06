"""Stage 1 - session bucketing (P1-T5, P1-T6).

Groups a capture into per-session packet streams: IKE messages for Stage 2,
ESP packets for Stage 3. Bucketing keys follow spec Section 4 -- the SPI pair
for IKEv2, the cookie pair for IKEv1, both read straight from the first sixteen
bytes of the header without decoding any payload.
"""

import struct
from dataclasses import dataclass, field
from typing import Literal

from core.ingestion.reader import Capture, CapturedPacket

ZERO_SPI = "0" * 16


@dataclass
class RawSession:
    """One IPsec session's raw packet streams, before any parsing."""

    session_id: str
    initiator_ip: str = ""
    responder_ip: str = ""
    ip_version: Literal["IPv4", "IPv6"] = "IPv4"
    nat_traversal: bool = False
    saw_ike_handshake: bool = True
    ike_messages: list[bytes] = field(default_factory=list)
    esp_packets: list[CapturedPacket] = field(default_factory=list)

    @property
    def peers(self) -> frozenset[str]:
        return frozenset({self.initiator_ip, self.responder_ip})


def _spi_pair(message: bytes) -> tuple[str, str]:
    """(initiator SPI, responder SPI) from an IKE header, as hex."""
    initiator, responder = struct.unpack("!8s8s", message[:16])
    return initiator.hex(), responder.hex()


def bucket_sessions(capture: Capture) -> list[RawSession]:
    """Every session in the capture, IKE and ESP streams attached."""
    sessions: dict[str, RawSession] = {}

    for packet in capture.ike:
        if len(packet.payload) < 16:
            continue
        initiator, responder = _spi_pair(packet.payload)

        # The first message carries a zero responder SPI. Key on the initiator
        # SPI so the reply lands in the same bucket, then adopt the responder
        # SPI once it is known.
        session = sessions.get(initiator)
        if session is None:
            session = RawSession(
                session_id=f"{initiator}-{responder}",
                initiator_ip=packet.src,
                responder_ip=packet.dst,
                ip_version=packet.ip_version,
            )
            sessions[initiator] = session
        elif responder != ZERO_SPI and session.session_id.endswith(ZERO_SPI):
            session.session_id = f"{initiator}-{responder}"

        session.nat_traversal = session.nat_traversal or packet.udp_port == 4500
        session.ike_messages.append(packet.payload)

    # ESP SPIs are independent of IKE SPIs and cannot be derived from the
    # handshake without the keys, so the peer address pair is the only link.
    by_peers = {s.peers: s for s in sessions.values()}
    mid_session: dict[frozenset[str], RawSession] = {}

    for packet in capture.esp:
        peers = frozenset({packet.src, packet.dst})
        session = by_peers.get(peers)
        if session is None:
            # ESP with no handshake in the capture: a mid-session start. The
            # spec is explicit that this is flagged, never guessed at.
            session = mid_session.get(peers)
            if session is None:
                left, right = sorted(peers)
                session = RawSession(
                    session_id=f"esp-{left}-{right}",
                    initiator_ip=packet.src,
                    responder_ip=packet.dst,
                    ip_version=packet.ip_version,
                    saw_ike_handshake=False,
                )
                mid_session[peers] = session
        session.esp_packets.append(packet)

    return list(sessions.values()) + list(mid_session.values())
