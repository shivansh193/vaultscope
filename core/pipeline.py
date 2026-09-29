"""The Analysis module: one capture in, one assessed :class:`Analysis` out.

    analysis = analyze_capture("capture.pcap")
    analysis.sessions    # every IKE SA, parsed, classified, scored
    analysis.anomalies   # cross-session attack indicators, with evidence frames
    analysis.stats       # what the capture held: packets, duration, IKE/ESP split

The capture is read exactly once (``core.capture``). Stage 1 buckets that read
into SAs, Stage 2 parses each SA with its own frame numbers, timestamps,
addresses and ESP, Stage 3 computes flow features from the same ESP frames,
Stage 4a fills what a truncated handshake hid, Stage 4b infers the tunnel's
traffic type, Stage 4c scores the session, and the anomaly detectors look
across the whole capture. Callers -- the API, the live-capture loop, the tests
-- get the finished result and never assemble a piece of it themselves.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from core.anomalies import detect_anomalies
from core.capture import read_capture
from core.classifiers import (
    MODE_MIN_CONFIDENCE,
    predict_ike_params,
    predict_mode,
    predict_traffic_type,
)
from core.flow import Flow, busiest_flow, flows_from_esp
from core.ike_parser import parse_ikev1_sessions, parse_ikev2_sessions
from core.ike_parser._transforms import EXCHANGE_IKE_SA_INIT
from core.ingestion import RawSession, bucket
from core.models import (
    AnomalyEvent,
    CaptureStats,
    FlowFeatures,
    TrafficPrediction,
    VPNSession,
)
from core.rules.engine import evaluate_rules

log = logging.getLogger(__name__)

CaptureSource = Literal["pcap_upload", "live_nic", "active_probe"]

# Stage 4a is a guess from message structure. Below this it is not a useful one.
PROTOCOL_FALLBACK_MIN_CONFIDENCE = 0.6
# No ESP means no side-channel to read. Say so rather than classify a zero vector.
NO_ESP_MODEL_VERSION = "no-esp-observed"


@dataclass
class Analysis:
    sessions: list[VPNSession] = field(default_factory=list)
    anomalies: list[AnomalyEvent] = field(default_factory=list)
    stats: CaptureStats = field(default_factory=CaptureStats)


def _parse(raw: RawSession) -> list[VPNSession]:
    parse = parse_ikev1_sessions if raw.ike_version == "IKEv1" else parse_ikev2_sessions
    try:
        return parse(raw)
    except Exception:  # one malformed SA must not sink the rest of the capture
        log.warning("Stage 2 failed on SA %s", raw.session_id, exc_info=True)
        return []


def _fill_from_structure(session: VPNSession, raw: RawSession) -> None:
    """Stage 4a: recover encryption / D-H group the parser could not decode.

    Only ever fills a field that is ``unknown``, only from an IKE_SA_INIT that
    is actually in the capture, and stamps ``confidence_source`` so every
    reader can tell an inference from an observation.
    """
    ike = session.ike
    gaps = [f for f in ("encryption", "dh_group") if getattr(ike, f) == "unknown"]
    if not gaps or not any(m.exchange_type == EXCHANGE_IKE_SA_INIT for m in raw.ike_messages):
        return
    guess = predict_ike_params(raw.ike_messages)
    if not guess or guess["confidence"] < PROTOCOL_FALLBACK_MIN_CONFIDENCE:
        return
    for f in gaps:
        setattr(ike, f, guess[f])
    ike.inferred_fields = sorted(set(ike.inferred_fields) | set(gaps))
    ike.confidence_source = "classifier"


def _classify(flow: Flow | None) -> tuple[FlowFeatures, TrafficPrediction]:
    if flow is None:
        return FlowFeatures(), TrafficPrediction(model_version=NO_ESP_MODEL_VERSION)
    known = set(FlowFeatures.model_fields)
    features = FlowFeatures(**{k: v for k, v in flow.features.items() if k in known})
    return features, TrafficPrediction(**predict_traffic_type(features.model_dump()))


def _infer_mode(session: VPNSession) -> None:
    """Fill an unobserved tunnel/transport mode from ESP sizes, marked inferred.

    IKEv2 negotiates mode inside the encrypted IKE_AUTH; tunnel mode's extra
    inner IP header still shows in the ESP packet sizes.
    """
    if session.ike.mode != "unknown":
        return
    guess = predict_mode(
        session.flow_features.model_dump(), session.ike.ip_version, session.ike.encryption
    )
    if guess is None or guess[1] < MODE_MIN_CONFIDENCE:
        return
    session.ike.mode, session.ike.mode_confidence = guess
    session.ike.inferred_fields = sorted({*session.ike.inferred_fields, "mode"})


def _orphan_sessions(orphans: list) -> list[VPNSession]:
    """One mid-session record per peer pair whose ESP no SA in the capture owns.

    Stage 1 already decided ownership (including the lone-tunnel-behind-NAT
    case), so this only groups what it left over -- never re-matches by peers.
    """
    by_peers: dict[frozenset[str], list] = {}
    for e in orphans:
        by_peers.setdefault(e.peers, []).append(e)
    sessions = []
    for esp in by_peers.values():
        raw = RawSession(session_id="", ike_version="IKEv2", esp_frames=esp)
        for session in parse_ikev2_sessions(raw):
            first = esp[0]
            session.session_id = f"esp-{first.spi or 0:08x}"
            session.initiator_ip, session.responder_ip = first.src_ip, first.dst_ip
            session.packet_refs = [e.frame for e in esp[:20]]
            session.flow_features, session.traffic_prediction = _classify(
                busiest_flow(flows_from_esp(esp))
            )
            sessions.append(session)
    return sessions


def analyze_capture(path: str | Path, source: CaptureSource = "pcap_upload") -> Analysis:
    """Analyse one capture end to end."""
    path = Path(path)
    read = read_capture(path)
    ingested = bucket(read)

    sessions: list[VPNSession] = []
    for raw in ingested.sessions:
        # The SA's own ESP, as Stage 1 assigned it -- not a second match by peers.
        flow = busiest_flow(flows_from_esp(raw.esp_frames))
        for session in _parse(raw):
            _fill_from_structure(session, raw)
            session.flow_features, session.traffic_prediction = _classify(flow)
            if flow is not None:
                _infer_mode(session)
            sessions.append(session)

    sessions += _orphan_sessions(ingested.orphan_esp)

    for session in sessions:
        session.capture_source = source
        session.capture_file = path.name
        session.security_assessment = evaluate_rules(session)

    return Analysis(
        sessions=sessions,
        anomalies=detect_anomalies(sessions),
        stats=CaptureStats(
            packets=read.packets_seen,
            ike_packets=len(read.ike),
            esp_packets=len(read.esp),
            duration_sec=round(read.duration_sec, 3),
            sessions=len(sessions),
            incomplete_sessions=sum(not s.ike.capture_complete for s in sessions),
            orphan_esp_packets=len(ingested.orphan_esp),
        ),
    )
