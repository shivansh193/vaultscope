"""Stage 4a + 4b - Classifiers (P2, Block A / @shivansh193).

Stage 4b  Traffic-Type Classifier -- the core ML component. Given a Stage 3
          flow feature vector, predict the traffic type inside the tunnel
          (VoIP | Video | Web | Email | ICMP | Chat).
Stage 4a  Protocol/Crypto Classifier -- RF fallback that recovers encryption /
          D-H group from IKE message *structure* when Stage 2 could not
          (truncated / malformed captures). ``predict_ike_params(messages)``.

Pipeline hooks
--------------
``core.pipeline`` calls ``predict_traffic_type(features_dict)`` -> feeds
``core.models.TrafficPrediction``. Both classifiers return a safe default until
``models/*.pkl`` exist (``python -m core.classifiers.train``).
"""

from __future__ import annotations

import functools
import logging

from .protocol import ProtocolClassifier, structural_features
from .traffic import TrafficClassifier

log = logging.getLogger(__name__)

__all__ = [
    "predict_traffic_type",
    "predict_ike_params",
    "TrafficClassifier",
    "ProtocolClassifier",
    "model_info",
]

_UNTRAINED = {"predicted_type": "Other", "confidence": 0.0, "model_version": "untrained"}


@functools.lru_cache(maxsize=1)
def _model() -> TrafficClassifier | None:
    try:
        return TrafficClassifier.load()
    except FileNotFoundError:
        return None
    except Exception:  # a corrupt / incompatible pickle must not sink the pipeline
        log.warning("traffic_classifier.pkl could not be loaded", exc_info=True)
        return None


@functools.lru_cache(maxsize=1)
def _protocol_model() -> ProtocolClassifier | None:
    try:
        return ProtocolClassifier.load()
    except FileNotFoundError:
        return None
    except Exception:
        log.warning("protocol_classifier.pkl could not be loaded", exc_info=True)
        return None


def predict_ike_params(messages) -> dict | None:
    """Stage 4a: best-guess {encryption, dh_group, confidence, confidence_source}
    from IKE message structure. ``None`` when the model is not trained."""
    pc = _protocol_model()
    if pc is None:
        return None
    return pc.predict(structural_features(list(messages)))


def predict_traffic_type(features: dict) -> dict:
    """{predicted_type, confidence, model_version} for one Stage 3 feature dict."""
    clf = _model()
    if clf is None:
        return dict(_UNTRAINED)
    label, confidence = clf.predict(features)
    return {
        "predicted_type": label,
        "confidence": confidence,
        "model_version": clf.model_version,
    }


def model_info() -> dict:
    clf = _model()
    if clf is None:
        return {"trained": False, **_UNTRAINED}
    return {
        "trained": True,
        "algo": clf.algo,
        "model_version": clf.model_version,
        "classes": clf.classes,
        "metrics": clf.metrics,
    }
