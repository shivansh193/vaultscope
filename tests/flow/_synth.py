"""Synthetic ESP flows with per-traffic-class metadata signatures.

The real dataset (Stage 0 testbed) supplies captured strongSwan traffic; until
those pcaps exist these hand-shaped flows let the Stage 3 tests assert the
feature maths and the class separations the spec calls out (VoIP constant-rate,
Video bursty, ICMP sparse, ...). Signatures follow product spec Section 4
"Stage 3" / Section 10 "Dataset Specification".
"""

from __future__ import annotations

import random

from core.flow.features import Packet

_UP, _DOWN = 1, -1


def synth_flow(kind: str, *, seconds: float = 30.0, seed: int = 0, start: float = 1_000_000.0):
    """A list[Packet] approximating ``kind`` traffic over ``seconds``."""
    rng = random.Random(seed)
    k = kind.lower()
    pkts: list[Packet] = []
    t = start

    if k == "voip":  # small, constant-rate, very regular, ~1:1 bidirectional
        step = 0.020  # 50 pps each way; the two streams are ~half a frame apart
        while t < start + seconds:
            pkts.append(Packet(t, rng.randint(190, 210), _UP))
            pkts.append(Packet(t + 0.010, rng.randint(190, 210), _DOWN))
            t += step

    elif k == "video":  # large, heavily bursty, down-heavy, high throughput
        while t < start + seconds:
            for _ in range(rng.randint(40, 80)):  # a GOP burst
                pkts.append(Packet(t, rng.randint(1300, 1500), _DOWN))
                t += 0.0006
            pkts.append(Packet(t, rng.randint(60, 120), _UP))  # ACK
            t += rng.uniform(0.25, 0.5)  # inter-burst gap

    elif k == "web":  # variable size, short bursts then idle, down-heavy
        while t < start + seconds:
            for _ in range(rng.randint(8, 18)):
                pkts.append(Packet(t, rng.randint(200, 1400), _DOWN))
                t += 0.002
            pkts.append(Packet(t, rng.randint(80, 300), _UP))
            t += rng.uniform(1.5, 3.5)  # user think-time

    elif k == "email":  # small up-bursts on send, then long idle, up-heavy
        while t < start + seconds:
            for _ in range(rng.randint(15, 30)):
                pkts.append(Packet(t, rng.randint(200, 700), _UP))
                t += 0.003
            pkts.append(Packet(t, rng.randint(60, 100), _DOWN))
            t += rng.uniform(5.0, 9.0)

    elif k == "icmp":  # tiny, fixed, sparse -- one echo/reply per second
        while t < start + seconds:
            pkts.append(Packet(t, 98, _UP))
            pkts.append(Packet(t + 0.01, 98, _DOWN))
            t += 1.0

    elif k == "chat":  # small, bursty, irregular, bidirectional
        while t < start + seconds:
            for _ in range(rng.randint(2, 6)):
                pkts.append(Packet(t, rng.randint(90, 180), rng.choice((_UP, _DOWN))))
                t += rng.uniform(0.05, 0.2)
            t += rng.uniform(2.0, 6.0)

    else:  # pragma: no cover
        raise ValueError(f"unknown traffic kind: {kind}")

    return pkts


TRAFFIC_KINDS = ("voip", "video", "web", "email", "icmp", "chat")
