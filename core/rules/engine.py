"""Stage 4c rule engine + scoring model (P3-T1, P3-T2).

Evaluates a :class:`~core.models.VPNSession` against the 15-rule table in
``rules.yaml`` and returns a populated
:class:`~core.models.SecurityAssessment`. The rule table is data: adding or
retuning a rule means editing the YAML, never this file.
"""

import functools
import re
from pathlib import Path
from typing import Any

import yaml

from core.models import (
    SEVERITY_ORDER,
    SEVERITY_PENALTY,
    Finding,
    SecurityAssessment,
    ThreatMatrixEntry,
    VPNSession,
)
from core.rules.remediation import generate_remediation

RULES_PATH = Path(__file__).with_name("rules.yaml")

# Likelihood/impact per severity for the report's threat matrix.
_THREAT_GRADE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("High", "High"),
    "HIGH": ("Med", "High"),
    "MEDIUM": ("Med", "Med"),
    "LOW": ("Low", "Low"),
}


@functools.cache
def load_rules() -> list[dict[str, Any]]:
    """Parse and validate the rule table once per process."""
    rules = yaml.safe_load(RULES_PATH.read_text())
    seen: set[str] = set()
    for rule in rules:
        if rule["id"] in seen:
            raise ValueError(f"duplicate rule id {rule['id']} in {RULES_PATH}")
        seen.add(rule["id"])
        if rule["severity"] not in SEVERITY_PENALTY:
            raise ValueError(f"rule {rule['id']} has unscoreable severity {rule['severity']}")
        for clause in rule["when"]:
            if clause["op"] not in _OPS:
                raise ValueError(f"rule {rule['id']} uses unknown op {clause['op']}")
    return rules


def _resolve(session: VPNSession, dotted: str) -> Any:
    """Walk a dotted path such as ``ike.dh_group`` into the session."""
    value: Any = session
    for part in dotted.split("."):
        value = getattr(value, part, None)
        if value is None:
            return None
    return value


def _op_regex(actual: Any, expected: Any) -> bool:
    return bool(re.search(str(expected), str(actual), re.IGNORECASE))


def _op_gt(actual: Any, expected: Any) -> bool:
    try:
        return float(actual) > float(expected)
    except (TypeError, ValueError):
        return False


# Booleans compare by identity of value, not truthiness: `anti_replay: false`
# must not be satisfied by 0, "", or None.
_OPS = {
    "eq": lambda actual, expected: actual == expected
    and isinstance(actual, bool) == isinstance(expected, bool),
    "in": lambda actual, expected: actual in expected,
    "gt": _op_gt,
    "regex": _op_regex,
}


def _matches(session: VPNSession, rule: dict[str, Any]) -> bool:
    """A rule fires only when every clause matches (clauses are ANDed)."""
    return all(
        _OPS[clause["op"]](_resolve(session, clause["field"]), clause["value"])
        for clause in rule["when"]
    )


def evaluate_rules(session: VPNSession) -> SecurityAssessment:
    """Score ``session`` against the rule table. Pure -- never mutates input.

    Scoring (spec Section 4): each triggered rule contributes a weighted
    penalty, the composite score is ``max(0, 100 - penalties)``, and any
    CRITICAL rule forces ``overall_severity`` to CRITICAL regardless of score.
    """
    vendor = session.ike.vendor
    findings = [
        Finding(
            rule_id=rule["id"],
            description=rule["description"],
            severity=rule["severity"],
            cve=rule.get("cve"),
            standard=rule.get("standard", ""),
            remediation=generate_remediation({"rule_id": rule["id"], "vendor": vendor}),
        )
        for rule in load_rules()
        if _matches(session, rule)
    ]

    penalty = sum(SEVERITY_PENALTY[f.severity] for f in findings)
    # R11 (>24h) and R12 (>8h) overlap by design -- the spec defines them as
    # independent thresholds, so a 24h+ lifetime is penalised by both.
    risk_score = max(0, 100 - penalty)

    if findings:
        overall = min((f.severity for f in findings), key=SEVERITY_ORDER.index)
    else:
        overall = "SAFE"

    return SecurityAssessment(
        risk_score=risk_score,
        overall_severity=overall,
        triggered_rules=[f.rule_id for f in findings],
        findings=findings,
        threat_matrix=[
            ThreatMatrixEntry(
                threat=f.description,
                likelihood=_THREAT_GRADE[f.severity][0],
                impact=_THREAT_GRADE[f.severity][1],
            )
            for f in findings
        ],
        ai_confidence=session.traffic_prediction.confidence,
    )
