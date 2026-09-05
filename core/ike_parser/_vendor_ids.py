"""Vendor ID payload fingerprinting (P2-T4).

IKE peers announce their implementation in Vendor ID (VID) payloads -- usually
``MD5(product string)`` with 0-4 version bytes appended, sometimes a literal
ASCII string. Matching the implementation lets Stage 4c fire vendor-specific
rules (R14: fragmented IKE on Cisco ASA -> CVE-2016-1287) and the Stage 5
remediation engine pick the right config-diff template.

Matched by hex *prefix* (version suffixes vary) or by an ASCII *substring*
(literal-string VIDs). First match wins; ``"unknown"`` otherwise.
"""

from __future__ import annotations

# (lowercase hex prefix, canonical vendor). Order matters only for overlap.
_HEX_PREFIXES: tuple[tuple[str, str], ...] = (
    ("882fe56d6fd20dbc2251613b2ebe5beb", "strongSwan"),
    ("4f45", "OpenSwan"),  # "OE" ... (Openswan/Libreswan literal, see ASCII too)
    ("12f5f28c457168a9702d9fe274cc", "Cisco"),  # Cisco Unity
    ("1f07f70eaa6514d3b0fa96542a50", "Cisco"),  # Cisco VPN 3000 / ASA / PIX
    ("3e984048101927ba7b1c17d9c4b6", "Cisco"),  # Cisco IOS
    ("409b8a300d0d2c479a0e30a2f24a", "Cisco"),  # Cisco ASA XAUTH
    ("cd60464335df21f87cfdb2fc68b6", "Cisco"),  # Cisco "DELETE-REASON"
    ("6d761ddc26aceca1b0ed11fabbb8", "Cisco"),  # Cisco "FlexVPN-Supported"
    ("699369228741c6d4ca094c93e242c9de", "Juniper"),  # NetScreen / Juniper SRX
    ("4865617274426561742d4e6f74696679", "Juniper"),  # "HeartBeat-Notify" NetScreen
    ("2a2bcac19b8e91b426107807e02e7249", "Juniper"),  # Juniper SRX
    ("8299031757a36082c6a621de000500", "Fortinet"),  # FortiGate
    ("1d6e178f6c2c0be284985465450fe9d4", "Fortinet"),
    ("da8e937880010000", "Palo Alto"),  # PAN-OS GlobalProtect-ish marker
    ("581cf88b0324eb1e5f95a9e2c39d", "Palo Alto"),
    ("1e2b516905991c7d7c96fcbfb587e461", "Microsoft"),  # draft-nat-t-ike-02
    ("8f8d83826d246b6fc7a8a6a428c11de8", "Microsoft"),  # MS NT5 ISAKMPOAKLEY
    ("4a131c81070358455c5728f20e95452f", "Microsoft"),  # RFC 3947 NAT-T
    ("90cb80913ebb696e086381b5ec427b1f", "Microsoft"),  # draft-nat-t-ike-03
)

# ASCII substrings, checked against the decoded VID bytes.
_ASCII_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"strongSwan", "strongSwan"),
    (b"Openswan", "OpenSwan"),
    (b"Libreswan", "Libreswan"),
    (b"CISCO", "Cisco"),
    (b"Cisco Systems", "Cisco"),
    (b"FRADE", "Cisco"),
    (b"Netscreen", "Juniper"),
    (b"NetScreen", "Juniper"),
    (b"SRX", "Juniper"),
    (b"FortiGate", "Fortinet"),
    (b"Fortinet", "Fortinet"),
    (b"Palo Alto", "Palo Alto"),
    (b"GlobalProtect", "Palo Alto"),
    (b"Microsoft", "Microsoft"),
    (b"MS NT5", "Microsoft"),
)


def _match_one(vid_hex: str) -> str | None:
    h = vid_hex.lower()
    for prefix, vendor in _HEX_PREFIXES:
        if h.startswith(prefix):
            return vendor
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return None
    for marker, vendor in _ASCII_MARKERS:
        if marker in raw:
            return vendor
    return None


def fingerprint_vendor(vid_hexes: list[str]) -> str:
    """Best implementation guess from a session's Vendor ID payloads."""
    for vid_hex in vid_hexes:
        vendor = _match_one(vid_hex)
        if vendor is not None:
            return vendor
    return "unknown"
