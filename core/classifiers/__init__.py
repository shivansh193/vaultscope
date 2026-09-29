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
from pathlib import Path

from .protocol import ProtocolClassifier, structural_features
from .traffic import TrafficClassifier

log = logging.getLogger(__name__)

__all__ = [
    "predict_traffic_type",
    "predict_ike_params",
    "predict_mode",
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


_MODE_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "mode_classifier.pkl"
# An inferred mode below this is left "unknown": a coin flip is not a finding.
MODE_MIN_CONFIDENCE = 0.7


@functools.lru_cache(maxsize=1)
def _mode_model() -> dict | None:
    """Tunnel/transport model from ``python -m core.classifiers.heldout --save-mode-model``."""
    try:
        import joblib

        return joblib.load(_MODE_PATH)
    except FileNotFoundError:
        return None
    except Exception:
        log.warning("mode_classifier.pkl could not be loaded", exc_info=True)
        return None


def predict_mode(features: dict, ip_version: str, encryption: str) -> tuple[str, float] | None:
    """(tunnel|transport, confidence) from ESP metadata, or None when untrained."""
    blob = _mode_model()
    if blob is None:
        return None
    from .heldout import mode_features

    row = mode_features(features, ip_version, encryption)
    model = blob["model"]
    probs = model.predict_proba([[row[n] for n in blob["feature_names"]]])[0]
    best = int(probs.argmax())
    return str(model.classes_[best]), round(float(probs[best]), 4)


def predict_ike_params(messages) -> dict | None:
    """Stage 4a: best-guess {encryption, dh_group, confidence, confidence_source}
    from IKE message structure. ``None`` when the model is not trained."""
    pc = _protocol_model()
    if pc is None:
        return None
    return pc.predict(structural_features(list(messages)))


# Below this winning probability the prediction is reported as uncertain rather
# than as a claim (reports and the dashboard say so; exposure scores it Low).
ABSTAIN_BELOW = 0.6


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
        "abstained": confidence < ABSTAIN_BELOW,
        "top_features": clf.explain(features, label),
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
