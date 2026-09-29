"""Build a capture that exercises every runtime anomaly detector.

    python scripts/make_attack_capture.py

The strongSwan dataset is lab-clean: one well-behaved tunnel per capture, so
none of the cross-session attack detectors has anything to find in it. This
script writes ``data/demo/attack_capture.pcap`` -- a short, clearly synthetic
capture of a gateway under attack -- so the anomaly path can be demonstrated
and its evidence frames checked in Wireshark.

The IKE messages come from the same byte-level builders the parser is tested
against (``tests/ike_parser/_build.py``); only addresses, SPIs and timing are
chosen here. Nothing in it is presented as captured traffic.

What is in it, and what should fire:

    AGGRESSIVE_MODE_PROBE  three IKEv1 Aggressive Mode attempts on one gateway
    TRANSFORM_BRUTEFORCE   one scanner offering four different suites
    DOWNGRADE_SUSPECTED    a branch that negotiates AES-GCM, then 3DES/MODP1024
    NAT_T_UNEXPECTED       a public initiator negotiating on UDP 4500
    REKEY_STORM            four SAs between one pair inside a minute
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "ike_parser"))

import _build as B  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

OUT = ROOT / "data" / "demo" / "attack_capture.pcap"
T0 = 1_790_000_000.0  # 2026-09-21 -- any fixed instant; keeps the file reproducible

GATEWAY = "10.30.0.1"
SCANNER = "203.0.113.66"  # TEST-NET-3 documentation range


def _spi(tag: int) -> bytes:
    return bytes([0xA0 | (tag >> 8), tag & 0xFF]) + bytes.fromhex("c0ffee00beef")


def _exchange(messages, src, dst, t, *, tag, port=500, gap=0.05):
    """One SA's messages, alternating direction, under initiator SPI ``tag``."""
    frames = []
    for i, msg in enumerate(messages):
        s, d = (src, dst) if i % 2 == 0 else (dst, src)
        load = _spi(tag) + msg[8:]
        if port == 4500:
            load = b"\x00" * 4 + load
        pkt = IP(src=s, dst=d) / UDP(sport=port, dport=port) / Raw(load=load)
        pkt.time = t + i * gap
        frames.append(pkt)
    return frames


def build() -> list:
    frames = []
    t = T0
    tag = 1

    # PSK-hash harvesting: repeated Aggressive Mode against one gateway.
    for attacker in ("198.51.100.7", "198.51.100.8", "198.51.100.9"):
        frames += _exchange(B.v1_aggressive_mode(), attacker, GATEWAY, t, tag=tag)
        t, tag = t + 4.0, tag + 1

    # Proposal enumeration: one scanner, four different transform sets.
    for preset in (
        "aes256gcm_ecp521_pfs",
        "aes128cbc_sha256_modp2048",
        "3des_sha1_modp1024",
        None,  # DES / MODP768 -- the oldest thing it can think of
    ):
        msgs = B.sa_init_pair(2, 1, 1, 1) if preset is None else B.sa_init_for_preset(preset)
        frames += _exchange(msgs, SCANNER, GATEWAY, t, tag=tag)
        t, tag = t + 1.5, tag + 1

    # Proposal stripping: the same branch pair, strong then weak.
    for preset in ("aes256gcm_ecp521_pfs", "3des_sha1_modp1024"):
        frames += _exchange(B.sa_init_for_preset(preset), "10.30.7.10", "10.30.7.20", t, tag=tag)
        t, tag = t + 90.0, tag + 1

    # NAT-T from a public address that has no reason to be behind NAT.
    frames += _exchange(
        B.sa_init_for_preset("aes128cbc_sha256_modp2048"),
        "81.2.69.160",  # a routable address: documentation ranges count as private
        GATEWAY,
        t,
        tag=tag,
        port=4500,
    )
    t, tag = t + 5.0, tag + 1

    # Rekey storm: four SAs between one pair within a minute.
    for _ in range(4):
        frames += _exchange(
            B.sa_init_for_preset("aes256gcm_ecp521_pfs"), "10.30.8.10", "10.30.8.20", t, tag=tag
        )
        t, tag = t + 12.0, tag + 1

    return frames


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    frames = build()
    wrpcap(str(OUT), frames)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(frames)} frames")
