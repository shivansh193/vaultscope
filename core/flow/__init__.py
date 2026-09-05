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

from ._capture import read_esp_packets
from .features import FEATURE_NAMES, Packet, feature_vector

__all__ = [
    "extract_features",
    "extract_features_by_flow",
    "feature_vector",
    "FEATURE_NAMES",
    "Packet",
]


def _packets(source) -> list[Packet]:
    if isinstance(source, str | os.PathLike):
        return [pkt for _spi, pkt in read_esp_packets(source)]
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

    by_spi: dict[str, list[Packet]] = {}
    for spi, pkt in read_esp_packets(source):
        key = f"{spi:08x}" if spi is not None else "unknown"
        by_spi.setdefault(key, []).append(pkt)
    return {spi: feature_vector(pkts) for spi, pkts in by_spi.items()}
