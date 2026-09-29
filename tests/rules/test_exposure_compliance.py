"""Metadata exposure, compliance baselines, and rules R19/R20."""

from core.models import CertInfo, FlowFeatures, TrafficPrediction
from core.rules.compliance import load_baselines
from core.rules.engine import evaluate_rules


def _by_id(result):
    return {c.baseline_id: c for c in result.compliance}


def test_clean_session_exposes_little(make_session):
    result = evaluate_rules(make_session())
    assert result.metadata_exposure.score == 0
    assert result.metadata_exposure.level == "Low"


def test_confident_traffic_prediction_is_high_exposure(make_session):
    session = make_session(
        initiator_ip="10.0.0.1",
        responder_ip="10.0.0.2",
        flow_features=FlowFeatures(pkt_total=500, flow_duration_sec=30, rate_pps=16.6),
        traffic_prediction=TrafficPrediction(predicted_type="VoIP", confidence=0.95),
    )
    exposure = evaluate_rules(session).metadata_exposure
    signals = {s.signal: s.level for s in exposure.signals}
    assert signals == {"traffic_type": "High", "endpoints": "Low", "timing": "Low"}
    assert exposure.level == "High"
    assert exposure.score == 45


def test_abstained_prediction_is_low_exposure(make_session):
    session = make_session(
        flow_features=FlowFeatures(pkt_total=50),
        traffic_prediction=TrafficPrediction(predicted_type="Web", confidence=0.9, abstained=True),
    )
    signals = {s.signal: s.level for s in evaluate_rules(session).metadata_exposure.signals}
    assert signals["traffic_type"] == "Low"


def test_aggressive_mode_leaks_identity_and_fires_r19(make_session):
    result = evaluate_rules(make_session(version="IKEv1", aggressive_mode=True, auth_method="RSA"))
    assert "R19" in result.triggered_rules
    assert "R06" not in result.triggered_rules  # R06 needs PSK
    assert any(s.signal == "identity" for s in result.metadata_exposure.signals)


def test_readable_cert_and_vendor_are_exposed(make_session):
    session = make_session(vendor="strongSwan", cert=CertInfo(subject="CN=gw.example"))
    signals = {s.signal for s in evaluate_rules(session).metadata_exposure.signals}
    assert {"identity", "implementation"} <= signals


def test_classical_key_exchange_fires_r20_only_when_known(make_session):
    assert "R20" in evaluate_rules(make_session(pqc_status="classical")).triggered_rules
    assert "R20" not in evaluate_rules(make_session(pqc_status="unknown")).triggered_rules
    assert "R20" not in evaluate_rules(make_session(pqc_status="hybrid")).triggered_rules


def test_every_baseline_reported_and_clean_session_passes_nist(make_session):
    result = evaluate_rules(make_session())
    ids = _by_id(result)
    assert set(ids) == {b["id"] for b in load_baselines()}
    assert ids["NIST-800-77r1"].status == "pass"


def test_weak_session_fails_baselines_with_rule_ids(make_session):
    ids = _by_id(evaluate_rules(make_session(encryption="3DES-CBC", dh_group="MODP2048")))
    assert ids["NIST-800-131A"].status == "fail"
    assert "R02" in ids["NIST-800-131A"].violations
    # BSI wants >= 3000-bit finite-field DH, so MODP2048 fails a requirement.
    assert "requires DH >= 3000 bit or ECP / Brainpool" in ids["BSI-TR-02102-3"].violations


def test_unknown_field_is_not_assessed_not_failed(make_session):
    ids = _by_id(evaluate_rules(make_session(encryption="unknown", dh_group="unknown")))
    assert ids["BSI-TR-02102-3"].status == "not_assessed"
    assert ids["CNSA-2.0"].unassessed == ["AES-256"]
