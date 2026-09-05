"""Synthetic per-class ESP flows for bootstrapping the Stage 4b classifier.

NOT the deliverable dataset -- that is captured strongSwan traffic from the
Stage 0 testbed (``data/pcaps`` + ``data/labels``). These shapes let
``core.classifiers.train`` produce a working model *now*, so the pipeline,
reports and dashboard show real predictions before the pcap dataset lands.

The signatures follow product spec Section 4 "Stage 3" / Section 10, but they
are deliberately *noisy and overlapping* -- packet-size spread, 5-15% loss,
timing jitter, variable flow length, and the odd class-atypical segment (a web
flow with a video-like burst, a chat flow that goes quiet like email). A model
that scores 1.0 on clean synthetic data is not evidence of anything; the point
is a believable bootstrap that retrains cleanly on real captures.

Every synthetic flow is run through the real ``core.flow.feature_vector`` so the
training features come from exactly the same code path as inference.
"""

from __future__ import annotations

import random

from core.flow.features import Packet

TRAFFIC_CLASSES: tuple[str, ...] = ("VoIP", "Video", "Web", "Email", "ICMP", "Chat")

_UP, _DOWN = 1, -1


def _jitter(rng: random.Random, base: float, frac: float = 0.30) -> float:
    return max(0.0, base * (1.0 + rng.uniform(-frac, frac)))


def _emit(rng: random.Random, pkts: list[Packet], t: float, size: int, direction: int) -> None:
    """Append a packet, but drop it 5-15% of the time (loss / capture gaps)."""
    if rng.random() > rng.uniform(0.05, 0.15):
        pkts.append(Packet(t, max(48, int(size)), direction))


def _voip(rng: random.Random, t: float, seconds: float) -> list[Packet]:
    pkts, end = [], t + seconds
    codec_size = rng.choice((160, 180, 200, 214))  # G.711 / G.729-ish frames
    step = rng.uniform(0.018, 0.024)
    while t < end:
        _emit(rng, pkts, t, rng.gauss(codec_size, 12), _UP)
        _emit(
            rng, pkts, t + step / 2 + rng.uniform(-0.003, 0.003), rng.gauss(codec_size, 12), _DOWN
        )
        t += _jitter(rng, step, 0.15)
    return pkts


def _video(rng: random.Random, t: float, seconds: float) -> list[Packet]:
    pkts, end = [], t + seconds
    while t < end:
        frame_size = rng.gauss(1350, 180)  # adaptive bitrate wobble
        for _ in range(int(_jitter(rng, rng.randint(20, 90)))):
            _emit(rng, pkts, t, rng.gauss(frame_size, 120), _DOWN)
            t += _jitter(rng, rng.uniform(0.0004, 0.0011))
        _emit(rng, pkts, t, rng.gauss(90, 30), _UP)
        t += _jitter(rng, rng.uniform(0.15, 0.7))
    return pkts


def _web(rng: random.Random, t: float, seconds: float) -> list[Packet]:
    pkts, end = [], t + seconds
    while t < end:
        # a page load: many small + a few large objects, then think-time. Some
        # loads are basically a sustained download (looks video-ish).
        big = rng.random() < 0.25
        for _ in range(int(_jitter(rng, rng.randint(6, 30)))):
            size = rng.gauss(1300, 200) if (big or rng.random() < 0.3) else rng.gauss(350, 260)
            _emit(rng, pkts, t, size, _DOWN)
            t += _jitter(rng, rng.uniform(0.001, 0.005))
        _emit(rng, pkts, t, rng.gauss(220, 120), _UP)
        t += _jitter(rng, rng.uniform(0.6, 4.5))
    return pkts


def _email(rng: random.Random, t: float, seconds: float) -> list[Packet]:
    pkts, end = [], t + seconds
    while t < end:
        for _ in range(int(_jitter(rng, rng.randint(8, 45)))):
            _emit(rng, pkts, t, rng.gauss(500, 260), _UP)
            t += _jitter(rng, rng.uniform(0.0015, 0.006))
        _emit(rng, pkts, t, rng.gauss(80, 25), _DOWN)
        t += _jitter(rng, rng.uniform(3.0, 11.0))
    return pkts


def _icmp(rng: random.Random, t: float, seconds: float) -> list[Packet]:
    pkts, end = [], t + seconds
    interval = rng.choice((1.0, 1.0, 0.5, 2.0))
    size = rng.choice((84, 98, 98, 98, 1042))  # occasional flood/large ping
    while t < end:
        _emit(rng, pkts, t, rng.gauss(size, 4), _UP)
        _emit(rng, pkts, t + rng.uniform(0.002, 0.05), rng.gauss(size, 4), _DOWN)
        t += _jitter(rng, interval, 0.2)
    return pkts


def _chat(rng: random.Random, t: float, seconds: float) -> list[Packet]:
    pkts, end = [], t + seconds
    while t < end:
        for _ in range(rng.randint(1, 9)):
            _emit(rng, pkts, t, rng.gauss(140, 45), rng.choice((_UP, _DOWN)))
            t += _jitter(rng, rng.uniform(0.03, 0.3))
        # sometimes a media attachment (a short burst of large packets)
        if rng.random() < 0.2:
            for _ in range(rng.randint(8, 25)):
                _emit(rng, pkts, t, rng.gauss(1200, 200), _UP)
                t += _jitter(rng, rng.uniform(0.001, 0.004))
        t += _jitter(rng, rng.uniform(1.0, 9.0))
    return pkts


_GENERATORS = {
    "VoIP": _voip,
    "Video": _video,
    "Web": _web,
    "Email": _email,
    "ICMP": _icmp,
    "Chat": _chat,
}


def synth_flow(traffic_class: str, *, seconds: float | None = None, seed: int = 0) -> list[Packet]:
    rng = random.Random(seed)
    dur = seconds if seconds is not None else rng.uniform(12.0, 55.0)
    return _GENERATORS[traffic_class](rng, 1_000_000.0 + rng.uniform(0, 5), dur)
