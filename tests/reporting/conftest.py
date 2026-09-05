"""Fixtures for Stage 5 report and export tests."""

import pytest

from core.models import IkeParams, TrafficPrediction, VPNSession
from core.rules.engine import evaluate_rules


def _assessed(session: VPNSession) -> VPNSession:
    session.security_assessment = evaluate_rules(session)
    return session


@pytest.fixture
def weak_session() -> VPNSession:
    return _assessed(
        VPNSession(
            session_id="sess-weak",
            capture_file="weak.pcap",
            timestamp="2026-09-05T10:00:00Z",
            initiator_ip="10.0.0.1",
            responder_ip="10.0.0.2",
            ike=IkeParams(
                version="IKEv1",
                aggressive_mode=True,
                auth_method="PSK",
                encryption="3DES-CBC",
                integrity="HMAC-SHA1",
                dh_group="MODP1024",
                pfs_status="disabled",
                sa_lifetime_sec=90000,
                vendor="Cisco ASA 9.8",
            ),
            traffic_prediction=TrafficPrediction(
                predicted_type="VoIP", confidence=0.82, model_version="rf-v1"
            ),
        )
    )


@pytest.fixture
def clean_session() -> VPNSession:
    return _assessed(
        VPNSession(
            session_id="sess-clean",
            timestamp="2026-09-05T10:05:00Z",
            initiator_ip="10.0.1.1",
            responder_ip="10.0.1.2",
            ike=IkeParams(vendor="strongSwan 5.9"),
            traffic_prediction=TrafficPrediction(
                predicted_type="Web", confidence=0.91, model_version="rf-v1"
            ),
        )
    )


@pytest.fixture
def sessions(weak_session, clean_session) -> list[VPNSession]:
    return [weak_session, clean_session]
