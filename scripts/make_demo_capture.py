"""Build a multi-session demo capture from the real dataset.

    python scripts/make_demo_capture.py

Every capture in ``data/pcaps`` holds exactly one tunnel, so ingesting one
yields a single-session dashboard. This concatenates a hand-picked spread --
weak crypto through strong, all six traffic classes -- and rewrites each
session's peer addresses onto its own subnet so the peer graph, the severity
spread and the traffic mix all have something to show.

The packets are real: nothing here is synthesised. Only the addresses are
rewritten, so sessions that were captured on the same harness slot do not
collide into one peer.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LABELS = ROOT / "data" / "labels"
PCAPS = ROOT / "data" / "pcaps"
OUT = ROOT / "data" / "demo" / "demo_capture.pcap"

# A spread a reviewer can read at a glance: the weak suites that trip the rule
# engine, the strong ones that do not, and every traffic class represented.
WANTED = [
    ("descbc_md5", "modp1024", "voip"),
    ("3descbc_sha1", "modp1024", "video"),
    ("aes128cbc_sha256", "modp1024", "web"),
    ("aes256cbc_sha256", "modp2048", "email"),
    ("aes128gcm", "ecp256", "chat"),
    ("aes256gcm", "ecp256", "icmp"),
    ("aes256gcm", "modp2048", "web"),
    ("3descbc_sha1", "ecp256", "voip"),
]


def pick() -> list[Path]:
    chosen: list[Path] = []
    for cipher, group, klass in WANTED:
        for label_path in sorted(LABELS.glob("*.json")):
            stem = label_path.stem
            # IPv4 only: the rewrite below assigns 10.20.x literals, which are
            # not valid on an IPv6 layer and silently corrupt the capture.
            if "ipv4" not in stem:
                continue
            if cipher in stem and group in stem and stem.endswith(f"__{klass}"):
                pcap = PCAPS / f"{stem}.pcap"
                if pcap.exists() and pcap not in chosen:
                    chosen.append(pcap)
                    break
    return chosen


def main() -> int:
    from scapy.layers.inet import IP
    from scapy.utils import rdpcap, wrpcap

    picks = pick()
    if not picks:
        print("no captures found; run scripts/generate_dataset.py first", file=sys.stderr)
        return 1

    merged = []
    summary = []
    for i, pcap in enumerate(picks):
        # Each session gets its own /24 so peers stay distinct in the graph.
        left, right = f"10.20.{i + 1}.10", f"10.20.{i + 1}.20"
        packets = rdpcap(str(pcap))
        seen: dict[str, str] = {}
        for packet in packets:
            if IP not in packet:
                continue
            layer = packet[IP]
            for field in ("src", "dst"):
                original = str(getattr(layer, field))
                if original not in seen:
                    seen[original] = left if len(seen) == 0 else right
                setattr(layer, field, seen[original])
            del packet[IP].chksum  # stale after the rewrite
        merged.extend(packets)

        label = json.loads((LABELS / f"{pcap.stem}.json").read_text())
        summary.append(
            f"  {left:<12} {label['config']['encryption']:<12} "
            f"{label['config']['dh_group']:<9} {label['traffic_class']}"
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT), merged)
    print(f"{OUT.relative_to(ROOT)}  {len(merged)} packets, {len(picks)} sessions")
    print("\n  peer         encryption   dh_group  traffic")
    print("\n".join(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
