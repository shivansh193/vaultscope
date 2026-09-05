"""P2-T5 / P2-T6 - Stage 3 ESP flow feature extractor.

Mandatory acceptance (spec Section 9): all features populated and numeric;
VoIP small + regular; Video vs Web separable on burst_gap_ratio; ICMP sparse.
"""

from __future__ import annotations

import _synth as S
import pytest

from core.flow import FEATURE_NAMES, extract_features, extract_features_by_flow, feature_vector
from core.flow.features import Packet
from core.models import FlowFeatures

ALL_KINDS = S.TRAFFIC_KINDS


@pytest.fixture(scope="module")
def vectors() -> dict[str, dict[str, float]]:
    return {k: feature_vector(S.synth_flow(k, seconds=40, seed=7)) for k in ALL_KINDS}


# --------------------------------------------------------------------------- #
# shape / contract                                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_all_features_populated_and_numeric(kind, vectors):
    fv = vectors[kind]
    assert set(fv) == set(FEATURE_NAMES)
    assert all(isinstance(fv[k], int | float) for k in FEATURE_NAMES)
    assert fv["pkt_total"] > 0 and fv["flow_duration_sec"] > 0


def test_vector_round_trips_into_canonical_flowfeatures(vectors):
    ff = FlowFeatures(**vectors["web"])
    assert ff.pkt_total == vectors["web"]["pkt_total"]


def test_empty_source_is_all_zero():
    fv = feature_vector([])
    assert set(fv) == set(FEATURE_NAMES)
    assert all(v == 0.0 for v in fv.values())


def test_single_packet_does_not_crash():
    fv = feature_vector([Packet(1.0, 200, 1)])
    assert fv["pkt_total"] == 1.0
    assert fv["iat_mean_ms"] == 0.0 and fv["burst_count"] == 0.0


# --------------------------------------------------------------------------- #
# class signatures (the discriminative properties the spec relies on)          #
# --------------------------------------------------------------------------- #


def test_voip_is_small_and_regular(vectors):
    v = vectors["voip"]
    assert v["pkt_size_mean"] < 300
    assert v["iat_std_ms"] < 5  # near-constant spacing
    assert 0.5 < v["dir_ratio"] < 2.0  # ~symmetric


def test_video_is_large_and_bursty(vectors):
    v = vectors["video"]
    assert v["pkt_size_mean"] > 1000
    assert v["burst_count"] >= 3
    assert v["dir_ratio"] < 0.5  # download-heavy


def test_video_burst_gap_ratio_higher_than_web(vectors):
    assert vectors["video"]["burst_gap_ratio"] > vectors["web"]["burst_gap_ratio"]


def test_icmp_is_sparse_low_rate(vectors):
    v = vectors["icmp"]
    assert v["rate_pps"] < 5
    assert v["pkt_size_std"] < 1  # fixed size
    assert v["burst_count"] == 0.0


def test_email_is_upstream_heavy(vectors):
    assert vectors["email"]["dir_ratio"] > 2.0


def test_web_and_video_are_separable(vectors):
    # payload_size_var_burst: video packets inside a burst are uniformly large,
    # web packets inside a burst vary wildly -> web has the higher variance
    assert vectors["web"]["payload_size_var_burst"] > vectors["video"]["payload_size_var_burst"]


# --------------------------------------------------------------------------- #
# pcap path (exercises core.flow._capture)                                     #
# --------------------------------------------------------------------------- #


def _write_esp_pcap(path, packets, *, up="10.0.0.1", down="10.0.0.2", spi=0xAABBCCDD):
    from scapy.layers.inet import IP
    from scapy.layers.ipsec import ESP
    from scapy.utils import wrpcap

    frames = []
    for p in packets:
        src, dst = (up, down) if p.direction >= 0 else (down, up)
        pad = max(0, p.size - 20 - 8)  # IP(20) + ESP header(8) approx
        pkt = IP(src=src, dst=dst) / ESP(spi=spi, seq=1, data=b"\x00" * pad)
        pkt.time = p.time
        frames.append(pkt)
    wrpcap(str(path), frames)
    return str(path)


def test_extract_features_from_pcap(tmp_path):
    pkts = S.synth_flow("voip", seconds=20, seed=1)
    path = _write_esp_pcap(tmp_path / "voip_esp.pcap", pkts)
    fv = extract_features(path)
    assert fv["pkt_total"] > 0
    assert fv["pkt_size_mean"] < 400  # small VoIP-ish frames
    assert 0.4 < fv["dir_ratio"] < 2.5


def test_extract_features_by_flow_groups_on_spi(tmp_path):
    from scapy.layers.inet import IP
    from scapy.layers.ipsec import ESP
    from scapy.utils import wrpcap

    frames = []
    for i, spi in enumerate((0x11111111, 0x22222222)):
        for j in range(30):
            pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ESP(spi=spi, seq=j, data=b"\x00" * 100)
            pkt.time = 1_000_000.0 + i * 100 + j * 0.1
            frames.append(pkt)
    path = str(tmp_path / "two_sa.pcap")
    wrpcap(path, frames)

    by_flow = extract_features_by_flow(path)
    assert set(by_flow) == {"11111111", "22222222"}
    assert all(v["pkt_total"] == 30.0 for v in by_flow.values())


def test_capture_with_no_esp_yields_zero_vector(tmp_path):
    # UDP/500 IKE traffic only -> Stage 3 sees nothing to measure
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    path = str(tmp_path / "ike_only.pcap")
    wrpcap(
        path, [IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(b"\x00" * 64)]
    )
    fv = extract_features(path)
    assert fv["pkt_total"] == 0.0
