"""Metadata-exposure assessment (PS item (d), "metadata exposure").

ESP hides the payload, not the conversation around it. This scores what a
passive on-path observer learns anyway -- which traffic type is riding the
tunnel, who the peers are, what gateway they run, when and how much they talk
-- from signals the pipeline has already recovered. Nothing here re-reads the
capture.
"""

from core.models import ExposureSignal, MetadataExposure, VPNSession

_WEIGHT = {"High": 35, "Med": 20, "Low": 5}
_ORDER = ["High", "Med", "Low"]

# A prediction this sure means packet sizes and timing alone name the traffic.
HIGH_CONFIDENCE = 0.8
MED_CONFIDENCE = 0.5


def _traffic_type(session: VPNSession) -> ExposureSignal | None:
    pred = session.traffic_prediction
    if session.flow_features.pkt_total == 0 or pred.predicted_type == "Other":
        return None
    detail = (
        f"Traffic inferable as {pred.predicted_type} ({pred.confidence:.0%} confidence) from "
        "ESP packet sizes and timing alone; no traffic-flow confidentiality padding hides it."
    )
    if pred.abstained or pred.confidence < MED_CONFIDENCE:
        return ExposureSignal(
            signal="traffic_type",
            level="Low",
            detail=f"Traffic type not reliably inferable ({pred.confidence:.0%} best guess).",
        )
    level = "High" if pred.confidence >= HIGH_CONFIDENCE else "Med"
    return ExposureSignal(signal="traffic_type", level=level, detail=detail)


def _identity(session: VPNSession) -> ExposureSignal | None:
    ike = session.ike
    if ike.version == "IKEv1" and ike.aggressive_mode:
        return ExposureSignal(
            signal="identity",
            level="High",
            detail="Peer identity (ID payload) sent in cleartext by IKEv1 Aggressive Mode.",
        )
    if ike.cert is not None and ike.cert.subject:
        return ExposureSignal(
            signal="identity",
            level="High",
            detail=f"Peer certificate readable on the wire: subject {ike.cert.subject}.",
        )
    return None


def _implementation(session: VPNSession) -> ExposureSignal | None:
    if session.ike.vendor in ("", "unknown"):
        return None
    return ExposureSignal(
        signal="implementation",
        level="Med",
        detail=(
            f"Gateway fingerprinted as {session.ike.vendor} from Vendor ID payloads and "
            "message framing -- narrows which exploits an attacker would try."
        ),
    )


def _endpoints(session: VPNSession) -> ExposureSignal | None:
    if not (session.initiator_ip and session.responder_ip):
        return None
    return ExposureSignal(
        signal="endpoints",
        level="Low",
        detail=(
            f"Tunnel endpoints {session.initiator_ip} <-> {session.responder_ip} are visible "
            "to any on-path observer (inherent to IPsec)."
        ),
    )


def _timing(session: VPNSession) -> ExposureSignal | None:
    flow = session.flow_features
    if flow.pkt_total == 0:
        return None
    return ExposureSignal(
        signal="timing",
        level="Low",
        detail=(
            f"Session activity observable: {flow.pkt_total} ESP packets over "
            f"{flow.flow_duration_sec:.0f}s ({flow.rate_pps:.1f} pkt/s)."
        ),
    )


def assess_metadata_exposure(session: VPNSession) -> MetadataExposure:
    """Score what leaks around the ciphertext. Pure -- never mutates input."""
    signals = [
        s
        for check in (_traffic_type, _identity, _implementation, _endpoints, _timing)
        if (s := check(session)) is not None
    ]
    if not signals:
        return MetadataExposure()
    return MetadataExposure(
        score=min(100, sum(_WEIGHT[s.level] for s in signals)),
        level=min((s.level for s in signals), key=_ORDER.index),
        signals=signals,
    )
