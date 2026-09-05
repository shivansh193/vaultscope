"""Stage 4a + 4b - Classifiers (P2, Block A / @shivansh193).

Stage 4b  Traffic-Type Classifier -- the core ML component. Given a Stage 3
          flow feature vector, predict the traffic type inside the tunnel
          (VoIP | Video | Web | Email | ICMP | Chat).
Stage 4a  Protocol/Crypto Classifier -- RF fallback for captures the
          deterministic IKE parser cannot fully resolve (P2-T9, later).

Pipeline hook
-------------
``core.pipeline`` calls ``predict_traffic_type(features_dict)`` and feeds the
result straight into ``core.models.TrafficPrediction``. Returns the untrained
default until ``models/traffic_classifier.pkl`` exists
(``python -m core.classifiers.train``).
"""

from __future__ import annotations

import functools
import logging

from .traffic import TrafficClassifier

log = logging.getLogger(__name__)

__all__ = ["predict_traffic_type", "TrafficClassifier", "model_info"]

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
