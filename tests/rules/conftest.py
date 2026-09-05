"""Fixtures for the Stage 4c rule-engine tests.

``make_session`` builds a deliberately CLEAN session, so any rule that fires in
a test fired because of the keyword the test passed in -- never because of a
default. Keep it that way.
"""

import pytest

from core.models import IkeParams, VPNSession

_IKE_FIELDS = set(IkeParams.model_fields)


@pytest.fixture
def make_session():
    def _make(session_id: str = "sess-test", **overrides) -> VPNSession:
        # Spec test cases pass `ike_version=`; the model field is `version`.
        if "ike_version" in overrides:
            overrides["version"] = overrides.pop("ike_version")
        ike = {k: overrides.pop(k) for k in list(overrides) if k in _IKE_FIELDS}
        return VPNSession(session_id=session_id, ike=IkeParams(**ike), **overrides)

    return _make


@pytest.fixture
def make_finding():
    def _make(rule_id: str = "R04", vendor: str = "unknown") -> dict:
        return {"rule_id": rule_id, "vendor": vendor}

    return _make
