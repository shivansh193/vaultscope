"""Pull ESP/AH packets out of a capture and reduce them to :class:`Packet`.

Kept apart from ``features.py`` so the feature maths stays dependency-free and
unit-testable on synthetic packet lists.
"""

from __future__ import annotations

import os
import struct

from .features import Packet

_NON_ESP_MARKER = b"\x00\x00\x00\x00"


def _spi_of(payload: bytes) -> int | None:
    return struct.unpack_from(">I", payload)[0] if len(payload) >= 4 else None


def read_esp_packets(
    path: str | os.PathLike,
) -> list[tuple[int | None, frozenset[str], Packet]]:
    """Return ``[(spi, peers, Packet), ...]`` for every ESP/AH packet in ``path``.

    Handles native ESP/AH (IP proto 50/51) and ESP-in-UDP (RFC 3948, UDP 4500
    with a non-zero first word). Direction is ``+1`` for packets sourced from
    the first ESP endpoint seen, ``-1`` for the reverse.

    ``peers`` is the unordered address pair carrying the packet. ESP SPIs are
    negotiated inside the encrypted exchange, so the peer pair is the only link
    between a data-plane flow and the IKE session that set it up -- and this
    walk already has both addresses in hand. Handing them back here spares
    every caller a second decode of the same file.
    """
    from scapy.layers.inet import IP, UDP  # noqa: PLC0415
    from scapy.layers.inet6 import IPv6  # noqa: PLC0415
    from scapy.utils import rdpcap  # noqa: PLC0415

    out: list[tuple[int | None, frozenset[str], Packet]] = []
    up_src: str | None = None

    for pkt in rdpcap(str(path)):
        if IP in pkt:
            ip, src, dst, proto = pkt[IP], pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        elif IPv6 in pkt:
            ip, src, dst, proto = pkt[IPv6], pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh
        else:
            continue

        spi: int | None = None
        is_esp = False
        if proto in (50, 51):  # ESP / AH
            is_esp = True
            body = bytes(ip.payload)
            spi = _spi_of(body)
        elif UDP in pkt and 4500 in (pkt[UDP].sport, pkt[UDP].dport):
            body = getattr(pkt[UDP].payload, "original", None) or bytes(pkt[UDP].payload)
            if len(body) >= 4 and body[:4] != _NON_ESP_MARKER:  # ESP-in-UDP, not IKE
                is_esp = True
                spi = _spi_of(body)
        if not is_esp:
            continue

        if up_src is None:
            up_src = src
        direction = 1 if src == up_src else -1
        out.append(
            (
                spi,
                frozenset({str(src), str(dst)}),
                Packet(time=float(pkt.time), size=len(pkt), direction=direction),
            )
        )

    return out
