"""Protocol-level anomaly detection (P3-T10).

Distinct from the Stage 4c rule engine: rules judge whether ONE session is
configured weakly, anomalies look ACROSS sessions in a capture for behaviour
that suggests an attacker probing the responder.
"""

import ipaddress
import uuid
from collections import defaultdict

from core.models import AnomalyEvent, VPNSession

# A "strong" cipher suite -- AEAD or AES-CBC with SHA-256+ and an ECP / MODP2048+
# group. Used by the downgrade detector to tell a capable peer from a weak one.
_WEAK_ENC = ("des", "3des", "null")
_WEAK_DH = ("modp768", "modp1024", "modp1536", "group 1", "group 2", "group 5")

# A single initiator offering this many distinct cipher/DH proposals to one
# responder is enumerating what the responder accepts, not configuring a tunnel.
TRANSFORM_BRUTEFORCE_THRESHOLD = 4

# Repeated Aggressive Mode attempts against one responder read as PSK-hash
# harvesting rather than a misconfigured client.
AGGRESSIVE_PROBE_THRESHOLD = 3


def _event(
    session_id: str,
    kind: str,
    severity: str,
    description: str,
    *,
    evidence_pkts: list[int] | None = None,
    timestamp: str = "",
) -> AnomalyEvent:
    return AnomalyEvent(
        anomaly_id=str(uuid.uuid4()),
        session_id=session_id,
        timestamp=timestamp,
        anomaly_type=kind,
        severity=severity,
        description=description,
        evidence_pkts=list(evidence_pkts or []),
    )


def _weak(s: VPNSession) -> bool:
    enc = (s.ike.encryption or "").lower()
    dh = (s.ike.dh_group or "").lower()
    return any(w in enc for w in _WEAK_ENC) or any(w in dh for w in _WEAK_DH)


def _is_public(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


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
                    evidence_pkts=session.packet_refs,
                    timestamp=session.timestamp,
                )
            )
    return events


def detect_transform_bruteforce(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """One peer pair negotiating many distinct transform sets = enumeration."""
    proposals: dict[tuple[str, str], set[tuple[str, str, str]]] = defaultdict(set)
    members: dict[tuple[str, str], list[VPNSession]] = defaultdict(list)

    for s in sessions:
        pair = (s.initiator_ip, s.responder_ip)
        proposals[pair].add((s.ike.encryption, s.ike.integrity, s.ike.dh_group))
        members[pair].append(s)

    events = []
    for pair, distinct in proposals.items():
        if len(distinct) >= TRANSFORM_BRUTEFORCE_THRESHOLD:
            for sess in members[pair]:
                events.append(
                    _event(
                        sess.session_id,
                        "TRANSFORM_BRUTEFORCE",
                        "HIGH",
                        f"{len(distinct)} distinct transform sets offered from "
                        f"{pair[0]} to {pair[1]} -- proposal enumeration",
                        evidence_pkts=sess.packet_refs,
                        timestamp=sess.timestamp,
                    )
                )
    return events


def detect_spi_collision(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """The same SPI pair reused across different peers implies replay or spoofing.

    A session_id IS the SPI pair (spec Section 5.1), so a session_id appearing
    against more than one peer pair cannot be a legitimate coincidence.
    """
    peers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    refs: dict[str, list[int]] = defaultdict(list)
    for s in sessions:
        peers[s.session_id].add((s.initiator_ip, s.responder_ip))
        refs[s.session_id].extend(s.packet_refs)

    return [
        _event(
            session_id,
            "SPI_COLLISION",
            "CRITICAL",
            f"SPI pair {session_id} observed across {len(pairs)} distinct peer "
            "pairs -- replayed or spoofed IKE",
            evidence_pkts=sorted(set(refs[session_id])),
        )
        for session_id, pairs in peers.items()
        if len(pairs) > 1
    ]


def detect_downgrade(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """The same peer pair negotiating both strong and weak crypto -- an on-path
    attacker stripping proposals so the responder settles on the weakest set."""
    by_pair: dict[tuple[str, str], list[VPNSession]] = defaultdict(list)
    for s in sessions:
        by_pair[(s.initiator_ip, s.responder_ip)].append(s)

    events: list[AnomalyEvent] = []
    for (init, resp), group in by_pair.items():
        weak = [s for s in group if _weak(s)]
        strong = [s for s in group if not _weak(s)]
        if weak and strong:
            for s in weak:
                events.append(
                    _event(
                        s.session_id,
                        "DOWNGRADE_SUSPECTED",
                        "HIGH",
                        f"{init} negotiated weak crypto ({s.ike.encryption} / "
                        f"{s.ike.dh_group}) with {resp} that also accepted a strong "
                        "suite -- possible proposal-stripping downgrade",
                        evidence_pkts=s.packet_refs,
                        timestamp=s.timestamp,
                    )
                )
    return events


def detect_nat_t_unexpected(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """NAT-Traversal negotiated where the initiator holds a public address --
    a peer that is not behind NAT should not be doing NAT-T."""
    return [
        _event(
            s.session_id,
            "NAT_T_UNEXPECTED",
            "MEDIUM",
            f"NAT-Traversal negotiated but initiator {s.initiator_ip} is a public "
            "address -- unexpected, possibly a spoofed or relayed peer",
            evidence_pkts=s.packet_refs,
            timestamp=s.timestamp,
        )
        for s in sessions
        if s.ike.nat_traversal and _is_public(s.initiator_ip)
    ]


REKEY_STORM_WINDOW_SEC = 60
REKEY_STORM_THRESHOLD = 4


def detect_rekey_storm(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """Many IKE SAs established between one peer pair inside a minute -- tunnel
    instability or forced-renegotiation abuse."""
    import datetime as dt

    by_pair: dict[tuple[str, str], list[VPNSession]] = defaultdict(list)
    for s in sessions:
        if s.timestamp:
            by_pair[(s.initiator_ip, s.responder_ip)].append(s)

    events: list[AnomalyEvent] = []
    for (init, resp), group in by_pair.items():
        times = sorted(dt.datetime.fromisoformat(s.timestamp) for s in group)
        if len(times) < REKEY_STORM_THRESHOLD:
            continue
        span = (times[-1] - times[0]).total_seconds()
        if span <= REKEY_STORM_WINDOW_SEC:
            for s in group:
                events.append(
                    _event(
                        s.session_id,
                        "REKEY_STORM",
                        "MEDIUM",
                        f"{len(group)} IKE SAs {init}->{resp} within {int(span)}s -- "
                        "tunnel instability or forced renegotiation",
                        evidence_pkts=s.packet_refs,
                        timestamp=s.timestamp,
                    )
                )
    return events


DETECTORS = (
    detect_aggressive_mode_probe,
    detect_transform_bruteforce,
    detect_spi_collision,
    detect_downgrade,
    detect_nat_t_unexpected,
    detect_rekey_storm,
)


def detect_anomalies(sessions: list[VPNSession]) -> list[AnomalyEvent]:
    """Run every detector over one capture's sessions."""
    return [event for detector in DETECTORS for event in detector(sessions)]
