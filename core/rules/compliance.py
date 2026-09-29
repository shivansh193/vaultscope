"""Per-baseline pass / fail over the rule findings (see compliance.yaml)."""

import functools
from pathlib import Path
from typing import Any

import yaml

from core.models import ComplianceResult, VPNSession

COMPLIANCE_PATH = Path(__file__).with_name("compliance.yaml")


@functools.cache
def load_baselines() -> list[dict[str, Any]]:
    from core.rules.engine import _OPS, load_rules

    known = {r["id"] for r in load_rules()}
    baselines = yaml.safe_load(COMPLIANCE_PATH.read_text())
    for b in baselines:
        unknown = set(b.get("violated_by", [])) - known
        if unknown:
            raise ValueError(f"baseline {b['id']} cites unknown rules {sorted(unknown)}")
        for clause in b.get("requires", []):
            if clause["op"] not in _OPS:
                raise ValueError(f"baseline {b['id']} uses unknown op {clause['op']}")
    return baselines


def assess_compliance(session: VPNSession, triggered: list[str]) -> list[ComplianceResult]:
    from core.rules.engine import _OPS, _resolve

    fired = set(triggered)
    results = []
    for b in load_baselines():
        violations = [r for r in b.get("violated_by", []) if r in fired]
        unassessed = []
        for clause in b.get("requires", []):
            actual = _resolve(session, clause["field"])
            if actual is None or actual == "unknown":
                unassessed.append(clause["label"])
            elif not _OPS[clause["op"]](actual, clause["value"]):
                violations.append(f"requires {clause['label']}")
        if violations:
            status = "fail"
        elif unassessed:
            status = "not_assessed"
        else:
            status = "pass"
        results.append(
            ComplianceResult(
                baseline_id=b["id"],
                name=b["name"],
                status=status,
                violations=violations,
                unassessed=unassessed,
            )
        )
    return results
