"""Full analysis pipeline: capture in, assessed sessions out (P3-T9).

This module is the ONLY place that knows whether Block A (Stage 1 ingestion,
Stage 2 IKE parser, Stage 3 flow features, Stage 4a/4b classifiers) exists yet.
Everything downstream -- the API, the DB, the reports -- consumes
:func:`analyze_capture` and is unaffected when the real components land.

Block A is owned by @shivansh193 and lands incrementally. Each stage is probed
independently, so a capture benefits from the IKE parser as soon as it exists
even while the classifier is still missing.

When the parser is unavailable the pipeline runs in FIXTURE MODE: sessions come
from ``data/mock/sessions.json`` rather than the uploaded capture. Fixture-mode
sessions are stamped ``ike.capture_complete = False`` and
``traffic_prediction.model_version = "fixture"`` so no caller, report or
dashboard can mistake them for a real decode.
"""

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from core.models import FlowFeatures, TrafficPrediction, VPNSession
from core.rules.engine import evaluate_rules

log = logging.getLogger(__name__)

MOCK_SESSIONS_PATH = Path(__file__).resolve().parent.parent / "data" / "mock" / "sessions.json"

CaptureSource = Literal["pcap_upload", "live_nic", "active_probe"]


def _load(module: str, attr: str) -> Callable | None:
    """Return a Block A entry point, or None while that stage is unbuilt."""
    try:
        return getattr(__import__(module, fromlist=[attr]), attr)
    except (ImportError, AttributeError):
        return None


PARSE_ENTRY_POINTS = ("parse_ikev2_sessions", "parse_ikev1_sessions")


def parser_available() -> bool:
    """True once Block A's Stage 2 parser is importable."""
    return any(_load("core.ike_parser", name) for name in PARSE_ENTRY_POINTS)


def _parse(path: Path) -> list[VPNSession] | None:
    """Every IKE SA in the capture, or None while the parser is unbuilt.

    Goes through Stage 1 when it is available: the ingestion engine buckets a
    capture into one RawSession per SA and carries each session's own peer
    addresses. Calling the parser on the file directly instead collapses a
    multi-tunnel capture onto whichever peers appeared first, because the
    parser's IP context is per-capture rather than per-SA.
    """
    parsers = [_load("core.ike_parser", name) for name in PARSE_ENTRY_POINTS]
    if not any(parsers):
        return None

    ingest = _load("core.ingestion", "ingest")
    if ingest is not None:
        by_version = {"IKEv1": parsers[1], "IKEv2": parsers[0]}
        try:
            sessions = []
            for raw in ingest(str(path)).sessions:
                parse = by_version.get(raw.ike_version)
                if parse is None:
                    continue
                for parsed in parse(raw.ike_messages):
                    parsed.initiator_ip = raw.initiator_ip or parsed.initiator_ip
                    parsed.responder_ip = raw.responder_ip or parsed.responder_ip
                    sessions.append(parsed)
            return sessions
        except Exception:
            log.warning(
                "Stage 1 ingestion failed on %s; parsing directly", path.name, exc_info=True
            )

    sessions = []
    for parse in parsers:
        if parse is None:
            continue
        try:
            sessions.extend(parse(str(path)))
        except Exception:  # one version failing must not sink the other
            log.warning("%s failed on %s", parse.__name__, path.name, exc_info=True)
    return sessions


def _classify(features: FlowFeatures) -> TrafficPrediction:
    predict = _load("core.classifiers", "predict_traffic_type")
    if predict is None:
        return TrafficPrediction()
    try:
        return TrafficPrediction(**predict(features.model_dump()))
    except Exception:
        log.warning("traffic classification failed; using default prediction", exc_info=True)
        return TrafficPrediction()


def _fixture_sessions() -> list[VPNSession]:
    """Sessions for FIXTURE MODE -- see the module docstring."""
    if not MOCK_SESSIONS_PATH.exists():
        return []
    records = json.loads(MOCK_SESSIONS_PATH.read_text())
    sessions = []
    for record in records:
        session = VPNSession(**record)
        session.ike.capture_complete = False
        session.traffic_prediction.model_version = "fixture"
        sessions.append(session)
    return sessions


def _flows(path: Path) -> dict:
    """Stage 3 flows keyed by SPI, each carrying its peer pair. Empty if unavailable."""
    extract = _load("core.flow", "extract_flows")
    if extract is None:
        return {}
    try:
        return extract(str(path))
    except Exception:
        log.warning("flow extraction failed on %s", path.name, exc_info=True)
        return {}


def _features_by_peers(flows: dict) -> dict[frozenset[str], FlowFeatures]:
    """The busiest flow between each peer pair, as a FlowFeatures.

    Built once per capture: matching every session against every flow would be
    quadratic on a capture with many SAs.
    """
    busiest: dict[frozenset[str], object] = {}
    for flow in flows.values():
        if not flow.features.get("pkt_total", 0):
            continue
        current = busiest.get(flow.peers)
        if current is None or flow.features["pkt_total"] > current.features["pkt_total"]:
            busiest[flow.peers] = flow

    known = set(FlowFeatures.model_fields)
    return {
        peers: FlowFeatures(**{k: v for k, v in flow.features.items() if k in known})
        for peers, flow in busiest.items()
    }


def analyze_capture(
    path: str | Path,
    source: CaptureSource = "pcap_upload",
) -> list[VPNSession]:
    """Analyse one capture end to end and return fully assessed sessions.

    Stage 1/2 -> Stage 3 -> Stage 4a/4b -> Stage 4c -> scored VPNSession.
    """
    path = Path(path)
    sessions = _parse(path)

    if sessions is None:
        log.warning(
            "Block A IKE parser unavailable -- running in FIXTURE MODE. "
            "Sessions are from %s, not from %s.",
            MOCK_SESSIONS_PATH.name,
            path.name,
        )
        sessions = _fixture_sessions()
    else:
        # Stage 3/4b run per SA. A capture with six tunnels in it has six
        # different answers, and stamping one capture-wide vector on every
        # session made them all predict the same traffic type.
        by_peers = _features_by_peers(_flows(path))
        for session in sessions:
            peers = frozenset({session.initiator_ip, session.responder_ip}) - {""}
            features = by_peers.get(peers) or FlowFeatures()
            session.flow_features = features
            session.traffic_prediction = _classify(features)

    for session in sessions:
        session.capture_source = source
        session.capture_file = path.name
        # Stage 4c always runs here: it is pure and depends only on ike.*
        session.security_assessment = evaluate_rules(session)
        session.security_assessment.ai_confidence = session.traffic_prediction.confidence

    return sessions
