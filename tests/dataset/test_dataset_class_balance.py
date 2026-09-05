"""Deliverable 1: the labeled dataset (spec Section 13)."""

import json
from pathlib import Path

import pytest

from testbed.generators.run import TRAFFIC_CLASSES
from testbed.labels import LABEL_KEYS

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parent.parent.parent
PCAPS = ROOT / "data" / "pcaps"
LABELS = ROOT / "data" / "labels"


def _labels():
    return [json.loads(p.read_text()) for p in sorted(LABELS.glob("*.json"))]


def test_dataset_class_balance():
    labels = _labels()
    assert len(labels) >= 300, f"deliverable 1 wants >= 300 captures, found {len(labels)}"

    counts = dict.fromkeys(TRAFFIC_CLASSES, 0)
    for label in labels:
        counts[label["traffic_class"]] += 1

    assert all(counts.values()), f"a class has no samples: {counts}"
    floor = 0.5 * (len(labels) / len(TRAFFIC_CLASSES))
    assert min(counts.values()) >= floor, f"class imbalance beyond 2:1: {counts}"


def test_every_pcap_has_a_label_and_vice_versa():
    assert {p.stem for p in PCAPS.glob("*.pcap")} == {p.stem for p in LABELS.glob("*.json")}


def test_label_schema_valid():
    for label in _labels():
        assert LABEL_KEYS <= set(label)
        assert label["config"]["encryption"]
        assert isinstance(label["substitution"], bool)


def test_the_matrix_is_actually_varied():
    configs = [label["config"] for label in _labels()]
    assert len({c["encryption"] for c in configs}) >= 4
    assert len({c["dh_group"] for c in configs}) == 3
    assert {c["pfs_status"] for c in configs} == {"enabled", "disabled"}


def test_substitution_classes_are_declared():
    for label in _labels():
        if label["traffic_class"] == "Chat":
            assert label["substitution"] is True


def test_captures_round_trip_through_our_own_parser():
    """A dataset our Stage 2 parser cannot read is not a dataset.

    Checks a sample rather than all 300: this reads pcaps off disk and the
    point is to catch a systemic capture fault, not to re-run Stage 2's suite.
    """
    from core.ike_parser import parse_ikev2_sessions

    pcaps = sorted(PCAPS.glob("*.pcap"))[:12]
    assert pcaps, "no captures to check"

    unparsed = []
    for pcap in pcaps:
        sessions = parse_ikev2_sessions(str(pcap))
        if not sessions or sessions[0].session_id == "esp-only":
            unparsed.append(pcap.name)
    assert not unparsed, f"captures with no recoverable IKE handshake: {unparsed}"


def test_parsed_crypto_matches_the_ground_truth_label():
    """The label says what was configured; the parser says what it saw. If
    those disagree, either the testbed or the parser is lying."""
    from core.ike_parser import parse_ikev2_sessions

    checked = 0
    for pcap in sorted(PCAPS.glob("*.pcap"))[:12]:
        label = json.loads((LABELS / f"{pcap.stem}.json").read_text())
        sessions = parse_ikev2_sessions(str(pcap))
        if not sessions or sessions[0].session_id == "esp-only":
            continue
        ike = sessions[0].ike
        assert ike.encryption == label["config"]["encryption"], pcap.name
        assert ike.dh_group == label["config"]["dh_group"], pcap.name
        checked += 1
    assert checked >= 5, f"only {checked} captures were comparable"
