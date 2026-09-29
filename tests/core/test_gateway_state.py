"""Gateway-state import: real strongSwan output fills what IKEv2 hides."""

from pathlib import Path

import pytest

from core.gateway_state import apply_gateway_state, parse_gateway_state
from core.models import IkeParams, VPNSession
from core.rules.engine import evaluate_rules

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "gateway"


def _session(init="10.90.10.2", resp="10.90.10.3", sid="3150ddecfe302c27-b7399df688decd18", **ike):
    base = {"mode": "unknown", "pfs_status": "unknown", "auth_method": None}
    return VPNSession(
        session_id=sid, initiator_ip=init, responder_ip=resp, ike=IkeParams(**{**base, **ike})
    )


def _parse(name):
    return parse_gateway_state((FIX / name).read_text())


def test_list_sas_fills_mode_by_ike_spi():
    (rec,) = _parse("list_sas.txt")
    assert rec.ike_spi_i == "3150ddecfe302c27"
    assert rec.values == {
        "version": "IKEv2",
        "mode": "transport",
    }  # no DH on first child: PFS unknown
    s = _session(init="1.1.1.1", resp="2.2.2.2")  # matched by SPI, not peers
    summary = apply_gateway_state([s], [rec])
    assert s.ike.mode == "transport" and s.ike.gateway_fields == ["mode"]
    assert summary["filled"] == {"mode": 1}


def test_list_conns_gives_auth_and_mode_by_peers():
    (rec,) = _parse("list_conns.txt")
    assert rec.values["auth_method"] == "PSK" and rec.values["mode"] == "transport"
    s = _session(init="10.90.11.3", resp="10.90.11.2")
    apply_gateway_state([s], [rec])
    assert s.ike.auth_method == "PSK"


def test_swanctl_conf_declares_pfs_from_esp_proposals():
    (rec,) = _parse("swanctl.conf")
    assert rec.values["pfs_status"] == "enabled"
    assert rec.values["mode"] == "tunnel" and rec.values["auth_method"] == "PSK"
    assert (rec.local, rec.remote) == ("10.0.0.2", "10.0.0.3")


def test_xfrm_reads_mode_and_anti_replay():
    (rec,) = _parse("xfrm_state.txt")
    assert rec.values == {"mode": "transport", "anti_replay": True}


def test_wire_disagreement_is_drift_and_fires_r21():
    (rec,) = _parse("list_sas.txt")
    s = _session(mode="tunnel")
    summary = apply_gateway_state([s], [rec])
    assert s.ike.mode == "tunnel"  # the wire wins; the gateway claim is recorded
    assert s.ike.gateway_mismatches == ["mode: wire tunnel, swanctl --list-sas transport"]
    assert summary["mismatches"]
    assert "R21" in evaluate_rules(s).triggered_rules


def test_gateway_value_replaces_an_inference():
    (rec,) = _parse("list_sas.txt")
    s = _session(mode="tunnel", inferred_fields=["mode"], mode_confidence=0.8)
    apply_gateway_state([s], [rec])
    assert s.ike.mode == "transport" and "mode" not in s.ike.inferred_fields
    assert s.ike.mode_confidence is None


@pytest.mark.parametrize("text", ["", "hello world", "src only"])
def test_unrecognised_text_parses_to_nothing(text):
    assert parse_gateway_state(text) == []
