"""Vendor-specific remediation engine (Stage 5, P3-T3).

Turns a finding into the exact config change for the fingerprinted vendor.
Templates live in ``remediation.yaml``; this module only resolves them.
"""

import functools
from collections.abc import Mapping
from pathlib import Path

import yaml

REMEDIATION_PATH = Path(__file__).with_name("remediation.yaml")
_RULES_PATH = Path(__file__).with_name("rules.yaml")

# Fingerprint strings vary ("Cisco ASA 9.8", "cisco-ftd"); match on a substring
# of the lowercased vendor and fall back to the RFC-compliant generic text.
_VENDOR_ALIASES: tuple[tuple[str, str], ...] = (
    ("cisco", "cisco"),
    ("strongswan", "strongswan"),
    ("juniper", "juniper"),
    ("srx", "juniper"),
    ("fortinet", "fortinet"),
    ("fortigate", "fortinet"),
    ("palo", "paloalto"),
    ("pan-os", "paloalto"),
)

_FALLBACK = (
    "Vendor could not be fingerprinted and no group-specific guidance applies. "
    "Bring the tunnel in line with RFC 8247: AES-256-GCM encryption, SHA-256 or "
    "stronger integrity, ECP256 (group 19) or better, PFS enabled, and an SA "
    "lifetime of 8 hours or less."
)


@functools.cache
def _templates() -> dict[str, dict[str, str]]:
    return yaml.safe_load(REMEDIATION_PATH.read_text())


@functools.cache
def _group_for_rule() -> dict[str, str]:
    return {r["id"]: r.get("remediation", "") for r in yaml.safe_load(_RULES_PATH.read_text())}


def canonical_vendor(vendor: str | None) -> str:
    """Map a raw vendor fingerprint onto a template key."""
    haystack = (vendor or "").lower()
    for needle, key in _VENDOR_ALIASES:
        if needle in haystack:
            return key
    return "generic"


def generate_remediation(finding, vendor: str | None = None) -> str:
    """Return the config diff for ``finding`` on its vendor.

    Accepts either a mapping (``{"rule_id": ..., "vendor": ...}``) or any object
    exposing ``rule_id``/``vendor`` attributes, so it works with both the raw
    parser output and a built :class:`core.models.Finding`.
    """
    if isinstance(finding, Mapping):
        rule_id = finding.get("rule_id", "")
        vendor = vendor if vendor is not None else finding.get("vendor")
    else:
        rule_id = getattr(finding, "rule_id", "")
        vendor = vendor if vendor is not None else getattr(finding, "vendor", None)

    group = _group_for_rule().get(rule_id)
    vendors = _templates().get(group or "", {})
    return (vendors.get(canonical_vendor(vendor)) or vendors.get("generic") or _FALLBACK).strip()
