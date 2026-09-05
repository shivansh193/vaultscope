"""Ground-truth labels for the dataset (P1-T3).

A label records what was *configured*, never what a parser recovered. Field
names and values reuse ``core.models.IkeParams`` vocabulary so a label can be
compared against a parsed session with no translation layer in between.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from testbed.config_generator import TunnelConfig
from testbed.generators.run import GENERATORS

LABEL_KEYS = {
    "pcap",
    "traffic_class",
    "substitution",
    "generator",
    "duration_sec",
    "config",
    "harness_notes",
    "captured_at",
    "testbed_commit",
}

# Disclosed on every record rather than left for a consumer to misread as a
# property of the configuration under test.
HARNESS_NOTES = [
    "IKE observed on UDP 4500: Docker's NAT triggers NAT-T. An artifact of the "
    "harness, not of the configuration under test.",
    "Lab-clean capture: no cross-traffic, so real-world classifier accuracy will be lower.",
]


def build_label(
    config: TunnelConfig,
    traffic_class: str,
    duration: int,
    pcap_name: str,
    testbed_commit: str,
) -> dict:
    generator = GENERATORS[traffic_class]
    return {
        "pcap": pcap_name,
        "traffic_class": traffic_class,
        "substitution": generator.substitution,
        "generator": f"{generator.name} -- {generator.description}",
        "duration_sec": duration,
        "config": {**config.label_config(), "ike_version": "IKEv2"},
        "harness_notes": list(HARNESS_NOTES),
        "captured_at": datetime.now(UTC).isoformat(),
        "testbed_commit": testbed_commit,
    }


def write_label(path: Path, label: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(label, indent=2) + "\n")
