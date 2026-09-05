"""Vendor-specific remediation engine (spec Section 9, P3-T3)."""

import pytest
import yaml

from core.rules.remediation import REMEDIATION_PATH, generate_remediation


@pytest.mark.parametrize(
    "vendor,expected_keyword",
    [
        ("Cisco ASA", "crypto ikev2 policy"),
        ("strongSwan", "proposals ="),
        ("Juniper SRX", "set security ike proposal"),
        ("Fortinet", "config vpn ipsec"),
        ("Palo Alto", "ike-crypto-profile"),
        ("unknown", "RFC 8247"),
    ],
)
def test_vendor_remediation_contains_correct_syntax(make_finding, vendor, expected_keyword):
    finding = make_finding(rule_id="R04", vendor=vendor)
    diff = generate_remediation(finding)
    assert expected_keyword in diff


def test_remediation_specifies_strong_dh_group(make_finding):
    finding = make_finding(rule_id="R04", vendor="strongSwan")
    diff = generate_remediation(finding)
    # must recommend group 19 or higher, not group 14
    assert "ecp256" in diff.lower() or "ecp521" in diff.lower() or "ecp384" in diff.lower()


def test_unfingerprinted_vendor_falls_back_to_generic(make_finding):
    for vendor in ("", "unknown", "SomeApplianceWeHaveNeverSeen"):
        diff = generate_remediation(make_finding(rule_id="R01", vendor=vendor))
        assert diff.strip()
        assert "RFC 8247" in diff


def test_vendor_matching_is_case_insensitive(make_finding):
    lower = generate_remediation(make_finding(rule_id="R04", vendor="cisco asa"))
    upper = generate_remediation(make_finding(rule_id="R04", vendor="CISCO ASA"))
    assert lower == upper
    assert "crypto ikev2 policy" in lower


def test_every_rule_resolves_to_a_nonempty_diff(make_finding):
    """No rule may produce an empty remediation -- the spec requires every
    finding to ship an actionable config change."""
    rules = yaml.safe_load((REMEDIATION_PATH.parent / "rules.yaml").read_text())
    for rule in rules:
        for vendor in ("Cisco ASA", "strongSwan", "Juniper SRX", "Fortinet", "Palo Alto", "x"):
            diff = generate_remediation(make_finding(rule_id=rule["id"], vendor=vendor))
            assert diff.strip(), f"empty remediation for {rule['id']} / {vendor}"


def test_every_group_defines_generic():
    groups = yaml.safe_load(REMEDIATION_PATH.read_text())
    for name, vendors in groups.items():
        assert vendors.get("generic", "").strip(), f"{name} has no generic fallback"


def test_unknown_rule_id_still_returns_guidance(make_finding):
    diff = generate_remediation(make_finding(rule_id="R99", vendor="Cisco ASA"))
    assert diff.strip()
