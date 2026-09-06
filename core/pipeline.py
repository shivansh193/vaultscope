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


def _esp_peers_by_spi(path: Path) -> dict[str, frozenset[str]]:
    """Map each ESP SPI to the address pair carrying it.

    ESP SPIs are negotiated inside the encrypted exchange, so they cannot be
    derived from the IKE messages -- the peer pair is the only link between a
    parsed session and its data plane.
    """
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import rdpcap
    except Exception:  # pragma: no cover - scapy always present in practice
        return {}

    import struct

    peers: dict[str, frozenset[str]] = {}
    try:
        packets = rdpcap(str(path))
    except Exception:
        return {}

    for packet in packets:
        if IP in packet:
            ip, proto = packet[IP], packet[IP].proto
        elif IPv6 in packet:
            ip, proto = packet[IPv6], packet[IPv6].nh
        else:
            continue

        payload = b""
        if proto in (50, 51):
            payload = bytes(ip.payload)
        elif UDP in packet and 4500 in (packet[UDP].sport, packet[UDP].dport):
            raw = bytes(packet[UDP].payload)
            if raw[:4] != b"\x00\x00\x00\x00":
                payload = raw
        if len(payload) < 4:
            continue

        spi = f"{struct.unpack_from('>I', payload)[0]:08x}"
        peers.setdefault(spi, frozenset({str(ip.src), str(ip.dst)}))
    return peers


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
        try:
            result = ingest(str(path))
            sessions: list[VPNSession] = []
            for raw in result.sessions:
                parse = _load(
                    "core.ike_parser",
                    "parse_ikev1_sessions"
                    if raw.ike_version == "IKEv1"
                    else "parse_ikev2_sessions",
                )
                if parse is None:
                    continue
                for parsed in parse(raw.ike_messages):
                    parsed.initiator_ip = raw.initiator_ip or parsed.initiator_ip
                    parsed.responder_ip = raw.responder_ip or parsed.responder_ip
                    sessions.append(parsed)
            if sessions:
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


def _flow_features_by_flow(path: Path) -> dict[str, dict]:
    """Stage 3 features per ESP flow, keyed by SPI. Empty if unavailable."""
    extract = _load("core.flow", "extract_features_by_flow")
    if extract is None:
        return {}
    try:
        return extract(str(path))
    except Exception:
        log.warning("per-flow extraction failed on %s", path.name, exc_info=True)
        return {}


def _session_features(
    session: VPNSession,
    by_flow: dict[str, dict],
    spi_peers: dict[str, frozenset[str]],
) -> FlowFeatures | None:
    """This session's own ESP flow, matched to it by peer pair.

    Returns None when the capture has no ESP for these peers -- an IKE-only
    capture -- so the caller can fall back rather than invent a flow.
    """
    if not by_flow:
        return None
    peers = frozenset({session.initiator_ip, session.responder_ip}) - {""}
    if len(peers) != 2:
        return None

    mine = [
        row
        for spi, row in by_flow.items()
        if spi_peers.get(spi) == peers and row.get("pkt_total", 0) > 0
    ]
    if not mine:
        return None

    busiest = max(mine, key=lambda row: row["pkt_total"])
    known = set(FlowFeatures.model_fields)
    return FlowFeatures(**{k: v for k, v in busiest.items() if k in known})


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
        by_flow = _flow_features_by_flow(path)
        spi_peers = _esp_peers_by_spi(path) if by_flow else {}
        capture_wide = None
        for session in sessions:
            features = _session_features(session, by_flow, spi_peers)
            if features is None:
                if capture_wide is None:
                    capture_wide = _flow_features(path)
                features = capture_wide
            session.flow_features = features
            session.traffic_prediction = _classify(features)

    for session in sessions:
        session.capture_source = source
        session.capture_file = path.name
        # Stage 4c always runs here: it is pure and depends only on ike.*
        session.security_assessment = evaluate_rules(session)
        session.security_assessment.ai_confidence = session.traffic_prediction.confidence

    return sessions
