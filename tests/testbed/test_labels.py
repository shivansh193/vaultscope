"""Ground-truth label schema (P1-T3)."""

import json

from testbed.config_generator import generate_configs
from testbed.labels import LABEL_KEYS, build_label, write_label


def _label(traffic_class="VoIP"):
    config = next(c for c in generate_configs() if c.suite.slug == "aes256gcm")
    return build_label(
        config, traffic_class, duration=30, pcap_name="x.pcap", testbed_commit="abc123"
    )


def test_label_carries_every_required_key():
    assert LABEL_KEYS <= set(_label())


def test_label_records_configuration_not_observation():
    label = _label()
    assert label["config"]["encryption"] == "AES-256-GCM"
    assert label["config"]["auth_method"] == "PSK"
    assert label["config"]["ike_version"] == "IKEv2"


def test_chat_is_flagged_as_a_substitution_and_voip_is_not():
    assert _label("Chat")["substitution"] is True
    assert _label("VoIP")["substitution"] is False


def test_nat_traversal_artifact_is_disclosed():
    notes = " ".join(_label()["harness_notes"]).lower()
    assert "4500" in notes and "artifact" in notes


def test_write_label_round_trips(tmp_path):
    path = tmp_path / "x.json"
    write_label(path, _label())
    assert json.loads(path.read_text())["traffic_class"] == "VoIP"
