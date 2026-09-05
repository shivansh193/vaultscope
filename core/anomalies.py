"""Protocol-level anomaly detection (P3-T10).

Distinct from the Stage 4c rule engine: rules judge whether ONE session is
configured weakly, anomalies look ACROSS sessions in a capture for behaviour
that suggests an attacker probing the responder.
"""

import uuid
from collections import defaultdict

from core.models import AnomalyEvent, VPNSession

# A single initiator offering this many distinct cipher/DH proposals to one
# responder is enumerating what the responder accepts, not configuring a tunnel.
TRANSFORM_BRUTEFORCE_THRESHOLD = 4

# Repeated Aggressive Mode attempts against one responder read as PSK-hash
# harvesting rather than a misconfigured client.
AGGRESSIVE_PROBE_THRESHOLD = 3


def _event(session_id: str, kind: str, severity: str, description: str) -> AnomalyEvent:
    return AnomalyEvent(
        anomaly_id=str(uuid.uuid4()),
        session_id=session_id,
        timestamp="",
        anomaly_type=kind,
        severity=severity,
        description=description,
        evidence_pkts=[],
    )


def detect_aggressive_mode_probe(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """IKEv1 Aggressive Mode attempts, escalating when repeated at one responder."""
    by_responder: dict[str, list[VPNSession]] = defaultdict(list)
    for s in sessions:
        if s.ike.version == "IKEv1" and s.ike.aggressive_mode:
            by_responder[s.responder_ip].append(s)

    events = []
    for responder, group in by_responder.items():
        repeated = len(group) >= AGGRESSIVE_PROBE_THRESHOLD
        for session in group:
            events.append(
                _event(
                    session.session_id,
                    "AGGRESSIVE_MODE_PROBE",
                    "CRITICAL" if repeated else "HIGH",
                    (
                        f"{len(group)} IKEv1 Aggressive Mode exchanges to {responder}"
                        if repeated
                        else f"IKEv1 Aggressive Mode exchange to {responder} exposes the PSK hash"
                    ),
                )
            )
    return events


def detect_transform_bruteforce(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """One peer pair negotiating many distinct transform sets = enumeration."""
    proposals: dict[tuple[str, str], set[tuple[str, str, str]]] = defaultdict(set)
    members: dict[tuple[str, str], list[str]] = defaultdict(list)

    for s in sessions:
        pair = (s.initiator_ip, s.responder_ip)
        proposals[pair].add((s.ike.encryption, s.ike.integrity, s.ike.dh_group))
        members[pair].append(s.session_id)

    events = []
    for pair, distinct in proposals.items():
        if len(distinct) >= TRANSFORM_BRUTEFORCE_THRESHOLD:
            for session_id in members[pair]:
                events.append(
                    _event(
                        session_id,
                        "TRANSFORM_BRUTEFORCE",
                        "HIGH",
                        f"{len(distinct)} distinct transform sets offered from "
                        f"{pair[0]} to {pair[1]} -- proposal enumeration",
                    )
                )
    return events


def detect_spi_collision(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """The same SPI pair reused across different peers implies replay or spoofing.

    A session_id IS the SPI pair (spec Section 5.1), so a session_id appearing
    against more than one peer pair cannot be a legitimate coincidence.
    """
    peers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for s in sessions:
        peers[s.session_id].add((s.initiator_ip, s.responder_ip))

    return [
        _event(
            session_id,
            "SPI_COLLISION",
            "CRITICAL",
            f"SPI pair {session_id} observed across {len(pairs)} distinct peer "
            "pairs -- replayed or spoofed IKE",
        )
        for session_id, pairs in peers.items()
        if len(pairs) > 1
    ]


DETECTORS = (
    detect_aggressive_mode_probe,
    detect_transform_bruteforce,
    detect_spi_collision,
)


def detect_anomalies(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """Run every detector over one capture's sessions."""
    return [event for detector in DETECTORS for event in detector(sessions)]
