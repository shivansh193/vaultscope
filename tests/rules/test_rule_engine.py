"""Stage 4c rule engine + scoring model (spec Section 9, P3-T1 + P3-T2)."""

from core.rules.engine import evaluate_rules


def test_des_encryption_triggers_r01_critical(make_session):
    session = make_session(encryption="DES-CBC")
    result = evaluate_rules(session)
    assert "R01" in result.triggered_rules
    assert result.overall_severity == "CRITICAL"


def test_dh_group2_triggers_r04_critical(make_session):
    session = make_session(dh_group="MODP1024")
    result = evaluate_rules(session)
    assert "R04" in result.triggered_rules
    assert result.overall_severity == "CRITICAL"


def test_critical_rule_overrides_composite_score(make_session):
    # Even with only one violation, a CRITICAL rule must set severity=CRITICAL.
    session = make_session(encryption="AES-256-GCM", dh_group="MODP1024")
    result = evaluate_rules(session)
    assert result.overall_severity == "CRITICAL"
    assert result.risk_score == 60  # 100 - 40, but severity is still CRITICAL


def test_pfs_unknown_not_penalised(make_session):
    session = make_session(pfs_status="unknown")
    result = evaluate_rules(session)
    assert "R10" not in result.triggered_rules  # no penalty for unknown


def test_clean_session_scores_100(make_session):
    session = make_session(
        ike_version="IKEv2",
        encryption="AES-256-GCM",
        dh_group="ECP521",
        pfs_status="enabled",
        auth_method="RSA",
        sa_lifetime_sec=3600,
    )
    result = evaluate_rules(session)
    assert result.risk_score == 100
    assert result.overall_severity == "SAFE"
    assert result.findings == []


# --- boundary and regression cases beyond the spec's five ---


def test_3des_is_r02_not_r01(make_session):
    """`3DES-CBC` contains the substring `DES`; it must not trip the CRITICAL rule."""
    result = evaluate_rules(make_session(encryption="3DES-CBC"))
    assert "R02" in result.triggered_rules
    assert "R01" not in result.triggered_rules
    assert result.overall_severity == "HIGH"


def test_sha256_does_not_trigger_sha1_rule(make_session):
    result = evaluate_rules(make_session(integrity="HMAC-SHA256"))
    assert "R09" not in result.triggered_rules


def test_sha1_triggers_r09(make_session):
    result = evaluate_rules(make_session(integrity="HMAC-SHA1"))
    assert "R09" in result.triggered_rules


def test_aggressive_mode_psk_triggers_r06(make_session):
    session = make_session(version="IKEv1", aggressive_mode=True, auth_method="PSK")
    result = evaluate_rules(session)
    assert {"R06", "R07"} <= set(result.triggered_rules)
    assert result.overall_severity == "CRITICAL"


def test_ikev1_without_aggressive_mode_is_high_not_critical(make_session):
    result = evaluate_rules(make_session(version="IKEv1", auth_method="RSA"))
    assert "R07" in result.triggered_rules
    assert "R06" not in result.triggered_rules
    assert result.overall_severity == "HIGH"


def test_psk_with_weak_dh_triggers_r13(make_session):
    result = evaluate_rules(make_session(auth_method="PSK", dh_group="MODP1024"))
    assert {"R04", "R13"} <= set(result.triggered_rules)


def test_long_lifetime_triggers_both_lifetime_rules(make_session):
    """Spec defines R11 (>86400) and R12 (>28800) as overlapping, so a 24h+
    lifetime trips both. Locked in deliberately -- see the note in engine.py."""
    result = evaluate_rules(make_session(sa_lifetime_sec=90000))
    assert {"R11", "R12"} <= set(result.triggered_rules)
    assert result.risk_score == 85  # 100 - 10 - 5


def test_fragmented_ike_only_flags_cisco(make_session):
    cisco = evaluate_rules(make_session(fragmented_ike=True, vendor="Cisco ASA"))
    other = evaluate_rules(make_session(fragmented_ike=True, vendor="strongSwan"))
    assert "R14" in cisco.triggered_rules
    assert "R14" not in other.triggered_rules


def test_anti_replay_disabled_triggers_r15(make_session):
    result = evaluate_rules(make_session(anti_replay=False))
    assert "R15" in result.triggered_rules


def test_score_floors_at_zero(make_session):
    """Penalties exceed 100 on a maximally broken session; score must clamp."""
    session = make_session(
        version="IKEv1",
        aggressive_mode=True,
        auth_method="PSK",
        encryption="DES-CBC",
        integrity="HMAC-MD5",
        dh_group="MODP768",
        pfs_status="disabled",
        sa_lifetime_sec=90000,
        anti_replay=False,
    )
    result = evaluate_rules(session)
    assert result.risk_score == 0
    assert result.overall_severity == "CRITICAL"


def test_findings_carry_metadata_and_remediation(make_session):
    result = evaluate_rules(make_session(dh_group="MODP1024", vendor="Cisco ASA"))
    finding = next(f for f in result.findings if f.rule_id == "R04")
    assert finding.severity == "CRITICAL"
    assert "RFC 8247" in finding.standard
    assert "crypto ikev2 policy" in finding.remediation


def test_cve_populated_where_spec_defines_one(make_session):
    result = evaluate_rules(make_session(encryption="3DES-CBC"))
    assert next(f for f in result.findings if f.rule_id == "R02").cve == "CVE-2016-2183"


def test_threat_matrix_populated_for_findings(make_session):
    result = evaluate_rules(make_session(dh_group="MODP1024"))
    assert len(result.threat_matrix) >= 1
    assert result.threat_matrix[0].likelihood in {"Low", "Med", "High"}


def test_evaluate_is_pure(make_session):
    """The engine must not mutate the session it is handed."""
    session = make_session(dh_group="MODP1024")
    before = session.model_dump_json()
    evaluate_rules(session)
    assert session.model_dump_json() == before
