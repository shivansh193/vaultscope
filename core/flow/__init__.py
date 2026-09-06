"""Stage 3 - ESP/AH Flow Feature Extractor (P2, Block A / @shivansh193).

The ESP payload is encrypted, so traffic characteristics are inferred from
metadata only: packet size distribution, inter-arrival timing, directionality,
and burstiness. Produces the 13-value vector consumed by the Stage 4b
traffic-type classifier -- keyed exactly to ``core.models.FlowFeatures``.

Public API
----------
    extract_features(source)          -> dict   (one vector for the whole capture)
    extract_features_by_flow(source)  -> {spi_hex: dict}   (per ESP SA)
    feature_vector(packets)           -> dict   (the maths, on a Packet iterable)
    FEATURE_NAMES

``source`` is a pcap path (``str`` / ``os.PathLike``) or an iterable of
:class:`~core.flow.features.Packet`. The pipeline (``core.pipeline``) calls
``extract_features(path)``.

See product spec Section 4 "Stage 3 - ESP/AH Flow Feature Extractor".
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass

from ._capture import read_esp_packets
from .features import FEATURE_NAMES, Packet, feature_vector

__all__ = [
    "busiest_flow",
    "extract_features",
    "extract_features_by_flow",
    "extract_flows",
    "Flow",
    "feature_vector",
    "FEATURE_NAMES",
    "Packet",
]


def _packets(source) -> list[Packet]:
    if isinstance(source, str | os.PathLike):
        return [pkt for _spi, _peers, pkt in read_esp_packets(source)]
    if isinstance(source, Iterable):
        return list(source)
    raise TypeError(f"unsupported flow source: {type(source)!r}")


def extract_features(source) -> dict[str, float]:
    """One Stage 3 feature vector aggregated over every ESP/AH packet in
    ``source``. Empty / IKE-only captures yield an all-zero vector."""
    return feature_vector(_packets(source))


def extract_features_by_flow(source) -> dict[str, dict[str, float]]:
    """A feature vector per ESP SA, keyed by SPI hex (``"deadbeef"``).

    Only meaningful for a pcap source; a bare ``Packet`` iterable carries no
    SPI, so it comes back under the single key ``"all"``.
    """
    if not isinstance(source, str | os.PathLike):
        return {"all": feature_vector(_packets(source))}

    return {spi: flow.features for spi, flow in extract_flows(source).items()}


@dataclass(frozen=True)
class Flow:
    """One ESP SA's Stage 3 vector, with the peers that carried it."""

    features: dict[str, float]
    peers: frozenset[str]


def extract_flows(source) -> dict[str, Flow]:
    """Per-SA feature vectors *and* their peer pairs, from one pass over the file.

    Stage 4b only needs the vectors, but anything joining a flow back to the
    IKE session that set it up needs the peers too -- SPIs are negotiated
    inside the encrypted exchange, so the address pair is the only link. Both
    come off the same walk; asking for them separately costs a second decode of
    the whole capture.
    """
    if not isinstance(source, str | os.PathLike):
        return {"all": Flow(feature_vector(_packets(source)), frozenset())}

    packets: dict[str, list[Packet]] = {}
    peers: dict[str, frozenset[str]] = {}
    for spi, pair, pkt in read_esp_packets(source):
        key = f"{spi:08x}" if spi is not None else "unknown"
        packets.setdefault(key, []).append(pkt)
        peers.setdefault(key, pair)
    return {spi: Flow(feature_vector(pkts), peers[spi]) for spi, pkts in packets.items()}


def busiest_flow(flows: dict[str, Flow], peers: frozenset[str] | None = None) -> Flow | None:
    """The flow carrying the most packets, optionally restricted to one peer pair.

    "The largest ESP flow is the traffic we care about" is a rule the pipeline,
    the training-table builder and the tests all rely on; it lives here so it
    is stated once.
    """
    candidates = [
        flow
        for flow in flows.values()
        if flow.features.get("pkt_total", 0) > 0 and (peers is None or flow.peers == peers)
    ]
    return max(candidates, key=lambda flow: flow.features["pkt_total"], default=None)
