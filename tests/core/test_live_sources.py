"""Live capture sources (core.live): each grows a capture file and nothing else."""

import subprocess
from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap, wrpcap

from core import live


def test_replay_writes_every_packet_in_order(tmp_path):
    src = tmp_path / "in.pcap"
    packets = [IP(dst="10.0.0.2") / UDP(dport=500, sport=500) for _ in range(25)]
    for i, p in enumerate(packets):
        p.time = 1_700_000_000 + i * 0.01
    wrpcap(str(src), packets)

    out = tmp_path / "out.pcap"
    source = live.ReplaySource(src, speed=1000)
    source.start(out)
    source._thread.join(timeout=10)
    assert not source.running and source.error is None
    assert [bytes(p) for p in rdpcap(str(out))] == [bytes(p) for p in packets]


def test_replay_caps_idle_gaps(tmp_path):
    src = tmp_path / "gappy.pcap"
    a, b = IP() / UDP(), IP() / UDP()
    a.time, b.time = 0, 3600  # an hour apart
    wrpcap(str(src), [a, b])
    source = live.ReplaySource(src, speed=1, max_gap_sec=0.05)
    source.start(tmp_path / "out.pcap")
    source._thread.join(timeout=3)
    assert not source.running


def test_replay_of_a_corrupt_capture_reports_why(tmp_path):
    src = tmp_path / "bad.pcap"
    src.write_bytes(b"not a capture at all")
    source = live.ReplaySource(src)
    source.start(tmp_path / "out.pcap")
    source._thread.join(timeout=3)
    assert source.error and source.error.startswith("replay failed")


def test_interfaces_parse_dumpcap_listing(monkeypatch):
    listing = "1. en0 (Wi-Fi)\n2. lo0 (Loopback)\n3. utun3\n"
    monkeypatch.setattr(live, "dumpcap_path", lambda: "/usr/bin/dumpcap")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=listing, stderr=""),
    )
    assert live.list_interfaces() == [
        {"name": "en0", "description": "Wi-Fi"},
        {"name": "lo0", "description": "Loopback"},
        {"name": "utun3", "description": ""},
    ]


def test_no_dumpcap_means_no_interfaces(monkeypatch):
    monkeypatch.setattr(live, "dumpcap_path", lambda: None)
    assert live.list_interfaces() == []


def test_capture_filter_keeps_only_ipsec():
    for term in ("udp port 500", "udp port 4500", "ip proto 50", "ip6 proto 50"):
        assert term in live.CAPTURE_FILTER


def test_wait_for_file_times_out_on_nothing(tmp_path: Path):
    assert live.wait_for_file(tmp_path / "never.pcap", timeout=0.1) is False
