"""ESP/AH flow feature maths (Stage 3).

Metadata only -- the ESP payload is ciphertext, so every feature comes from
packet *size*, *timing* and *direction*. The 13 outputs are keyed exactly to
``core.models.FlowFeatures`` (the pipeline contract); see the product spec
Section 4 "Stage 3" for what each one buys the Stage 4b classifier.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

FEATURE_NAMES: tuple[str, ...] = (
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_p10",
    "pkt_size_p90",
    "iat_mean_ms",
    "iat_std_ms",
    "dir_ratio",
    "burst_count",
    "burst_gap_ratio",
    "payload_size_var_burst",
    "flow_duration_sec",
    "pkt_total",
    "rate_pps",
)

# spec: a burst event is > 10 packets inside a 100 ms window
_BURST_WINDOW_SEC = 0.100
_BURST_MIN_PKTS = 10

_ZERO_VECTOR: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)


@dataclass(frozen=True)
class Packet:
    """One captured ESP/AH packet, reduced to what Stage 3 needs.

    ``direction`` is ``+1`` for initiator->responder ("up") and ``-1`` for the
    reverse; ``size`` is the on-wire IP packet length in bytes.
    """

    time: float  # epoch seconds
    size: int
    direction: int


def _percentile(sorted_vals: Sequence[float], q: float) -> float:
    """Linear-interpolation percentile (numpy 'linear' method), no numpy dep."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = q / 100.0 * (len(sorted_vals) - 1)
    lo = int(pos)
    frac = pos - lo
    if lo + 1 >= len(sorted_vals):
        return float(sorted_vals[-1])
    return float(sorted_vals[lo] + frac * (sorted_vals[lo + 1] - sorted_vals[lo]))


def _burst_intervals(times: Sequence[float]) -> list[tuple[float, float]]:
    """Merge every 100 ms window that holds > 10 packets into burst intervals.

    Two pointers over the sorted timestamps: whenever ``[t_i, t_i + 100ms]``
    contains at least 11 packets, that span is a burst; overlapping spans merge.
    """
    intervals: list[tuple[float, float]] = []
    n = len(times)
    j = 0
    for i in range(n):
        while j < n and times[j] - times[i] <= _BURST_WINDOW_SEC:
            j += 1
        if j - i > _BURST_MIN_PKTS:
            start, end = times[i], times[j - 1]
            if intervals and start <= intervals[-1][1]:
                intervals[-1] = (intervals[-1][0], max(intervals[-1][1], end))
            else:
                intervals.append((start, end))
    return intervals


def feature_vector(packets: Iterable[Packet]) -> dict[str, float]:
    """The 13-value Stage 3 feature vector for one flow (or a whole capture)."""
    pkts = sorted(packets, key=lambda p: p.time)
    if not pkts:
        return dict(_ZERO_VECTOR)

    sizes = [p.size for p in pkts]
    times = [p.time for p in pkts]
    total = len(pkts)
    duration = times[-1] - times[0]

    sorted_sizes = sorted(sizes)
    size_mean = statistics.fmean(sizes)
    size_std = statistics.pstdev(sizes) if total > 1 else 0.0

    iats_ms = [(times[k] - times[k - 1]) * 1000.0 for k in range(1, total)]
    iat_mean = statistics.fmean(iats_ms) if iats_ms else 0.0
    iat_std = statistics.pstdev(iats_ms) if len(iats_ms) > 1 else 0.0

    bytes_up = sum(p.size for p in pkts if p.direction >= 0)
    bytes_down = sum(p.size for p in pkts if p.direction < 0)
    # bytes up / bytes down; one-directional flows saturate rather than divide by 0
    if bytes_down:
        dir_ratio = bytes_up / bytes_down
    elif bytes_up:
        dir_ratio = float(total)  # all upstream: a large, finite ratio
    else:
        dir_ratio = 0.0

    intervals = _burst_intervals(times)
    burst_count = len(intervals)
    if burst_count:
        durations = [e - s for s, e in intervals]
        gaps = [intervals[k][0] - intervals[k - 1][1] for k in range(1, burst_count)]
        mean_dur = statistics.fmean(durations)
        mean_gap = statistics.fmean(gaps) if gaps else 0.0
        burst_gap_ratio = mean_dur / mean_gap if mean_gap > 0 else float(burst_count)
        in_burst = [p.size for p in pkts if any(s <= p.time <= e for s, e in intervals)]
        payload_size_var_burst = statistics.pvariance(in_burst) if len(in_burst) > 1 else 0.0
    else:
        burst_gap_ratio = 0.0
        payload_size_var_burst = 0.0

    return {
        "pkt_size_mean": round(size_mean, 4),
        "pkt_size_std": round(size_std, 4),
        "pkt_size_p10": round(_percentile(sorted_sizes, 10), 4),
        "pkt_size_p90": round(_percentile(sorted_sizes, 90), 4),
        "iat_mean_ms": round(iat_mean, 4),
        "iat_std_ms": round(iat_std, 4),
        "dir_ratio": round(dir_ratio, 4),
        "burst_count": float(burst_count),
        "burst_gap_ratio": round(burst_gap_ratio, 4),
        "payload_size_var_burst": round(payload_size_var_burst, 4),
        "flow_duration_sec": round(duration, 4),
        "pkt_total": float(total),
        "rate_pps": round(total / duration, 4) if duration > 0 else 0.0,
    }
