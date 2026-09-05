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
from typing import Any, Literal

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

    Both entry points already emit a canonical :class:`VPNSession` with the
    ``ike`` block filled (including ``capture_complete`` for partial decodes),
    so there is nothing to adapt here. A capture carries IKEv1 or IKEv2, not
    both, so running both parsers costs one extra empty read and spares the
    pipeline a version guess.
    """
    parsers = [_load("core.ike_parser", name) for name in PARSE_ENTRY_POINTS]
    if not any(parsers):
        return None
    sessions: list[VPNSession] = []
    for parse in parsers:
        if parse is None:
            continue
        try:
            sessions.extend(parse(str(path)))
        except Exception:  # one version failing must not sink the other
            log.warning("%s failed on %s", parse.__name__, path.name, exc_info=True)
    return sessions


def _flow_features(source: Any) -> FlowFeatures:
    extract = _load("core.flow", "extract_features")
    if extract is None:
        return FlowFeatures()
    try:
        return FlowFeatures(**extract(source))
    except Exception:  # a half-built extractor must not sink the whole capture
        log.warning("flow feature extraction failed; using empty features", exc_info=True)
        return FlowFeatures()


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
        # Stage 3/4b are per-capture, not per-SA, until Block A groups flows by SPI.
        features = _flow_features(path)
        prediction = _classify(features)
        for session in sessions:
            session.flow_features = features
            session.traffic_prediction = prediction

    for session in sessions:
        session.capture_source = source
        session.capture_file = path.name
        # Stage 4c always runs here: it is pure and depends only on ike.*
        session.security_assessment = evaluate_rules(session)
        session.security_assessment.ai_confidence = session.traffic_prediction.confidence

    return sessions
