"""P2-T7 / P2-T8 - Stage 4b traffic-type classifier.

Acceptance (spec Section 9): predicts all six classes on clear-signal input,
high confidence on the easy classes, macro-F1 above the honest 0.70 bar, and
the judge-facing artifacts exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.classifiers import model_info, predict_traffic_type
from core.classifiers._synthetic import TRAFFIC_CLASSES, synth_flow
from core.classifiers.dataset import rows_to_matrix, synthetic_table
from core.classifiers.traffic import TrafficClassifier
from core.flow import FEATURE_NAMES, feature_vector

MODELS = Path(__file__).resolve().parent.parent.parent / "models"


def _clear_vector(cls: str, seed: int) -> dict:
    """A low-noise flow for ``cls`` -- long, no class contamination."""
    return feature_vector(synth_flow(cls, seconds=45.0, seed=seed))


# --------------------------------------------------------------------------- #
# the shipped model                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    not (MODELS / "traffic_classifier.pkl").exists(),
    reason="run `python -m core.classifiers.train` first",
)
class TestShippedModel:
    def test_predicts_all_six_classes(self):
        for i, cls in enumerate(TRAFFIC_CLASSES):
            out = predict_traffic_type(_clear_vector(cls, seed=5000 + i))
            assert out["predicted_type"] == cls, out
            assert out["confidence"] >= 0.4

    def test_easy_classes_are_high_confidence(self):
        # spec: "VoIP, ICMP easy; Video vs Web hardest"
        for cls in ("ICMP", "Video"):
            out = predict_traffic_type(_clear_vector(cls, seed=6000))
            assert out["predicted_type"] == cls
            assert out["confidence"] >= 0.8

    def test_f1_macro_above_threshold(self):
        metrics = json.loads((MODELS / "eval_metrics.json").read_text())
        assert metrics["f1_macro"] >= 0.70  # honest bar, not overclaimed

    def test_confusion_matrix_artifact_is_shaped_right(self):
        cm = json.loads((MODELS / "confusion_matrix.json").read_text())
        n = len(cm["labels"])
        assert n == 6
        assert len(cm["matrix"]) == n and all(len(row) == n for row in cm["matrix"])

    def test_model_info_reports_trained(self):
        info = model_info()
        assert info["trained"] is True
        assert set(info["classes"]) == set(TRAFFIC_CLASSES)


# --------------------------------------------------------------------------- #
# training (fast, self-contained -- does not touch models/)                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def small_split():
    from sklearn.model_selection import train_test_split

    x, y = synthetic_table(70, seed=1)
    xt, xe, yt, ye = train_test_split(x, y, test_size=0.25, random_state=1, stratify=y)
    return (xt, yt), (xe, ye)


def test_train_auto_picks_a_model_and_clears_070(small_split):
    from sklearn.metrics import f1_score

    (xt, yt), (xe, ye) = small_split
    clf = TrafficClassifier.train(xt, yt, algo="auto", seed=1, eval_x=xe, eval_y=ye)
    assert clf.algo in ("rf", "xgb")
    preds = [clf.predict(r)[0] for r in xe]
    assert f1_score(ye, preds, average="macro") >= 0.70


def test_rf_exposes_feature_importances(small_split):
    (xt, yt), _ = small_split
    clf = TrafficClassifier._fit_one("rf", xt, yt, seed=1, model_version="t")
    imp = clf.feature_importances()
    assert set(imp) == set(FEATURE_NAMES)
    assert abs(sum(imp.values()) - 1.0) < 0.05


def test_xgboost_variant_trains_and_predicts(small_split):
    (xt, yt), (xe, _ye) = small_split
    clf = TrafficClassifier._fit_one("xgb", xt, yt, seed=1, model_version="t")
    label, conf = clf.predict(xe[0])
    assert label in TRAFFIC_CLASSES
    assert 0.0 <= conf <= 1.0


def test_save_load_round_trip(tmp_path, small_split):
    (xt, yt), (xe, _ye) = small_split
    clf = TrafficClassifier.train(xt, yt, algo="rf", seed=1)
    p = clf.save(tmp_path / "m.pkl")
    again = TrafficClassifier.load(p)
    assert again.classes == clf.classes
    assert again.predict(xe[0]) == clf.predict(xe[0])


def test_predict_untrained_is_safe(monkeypatch):
    import core.classifiers as cc

    cc._model.cache_clear()
    monkeypatch.setattr(cc.TrafficClassifier, "load", staticmethod(_raise_fnf))
    out = predict_traffic_type(dict.fromkeys(FEATURE_NAMES, 0.0))
    assert out == {"predicted_type": "Other", "confidence": 0.0, "model_version": "untrained"}
    cc._model.cache_clear()


def _raise_fnf(*_a, **_k):
    raise FileNotFoundError


def test_rows_to_matrix_orders_columns():
    row = dict.fromkeys(FEATURE_NAMES, 0.0)
    row["pkt_size_mean"] = 123.0
    mat = rows_to_matrix([row])
    assert mat[0][FEATURE_NAMES.index("pkt_size_mean")] == 123.0
