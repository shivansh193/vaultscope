"""Stage 4b - Traffic-Type Classifier (the core AI component).

Given a Stage 3 flow feature vector, predict what application traffic is running
inside the encrypted tunnel: VoIP | Video | Web | Email | ICMP | Chat.

RandomForest and XGBoost are both trained; the one with the higher macro-F1 on
the validation split wins (``TrafficClassifier.train(..., algo="auto")``).
Interpretable, fast, small-dataset friendly -- and RF gives feature importances
for the judge demo. A 1D-CNN over raw packet-size sequences is the stretch goal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib

from core.flow.features import FEATURE_NAMES

from .dataset import rows_to_matrix

_DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "traffic_classifier.pkl"


@dataclass
class TrafficClassifier:
    model: object  # a fitted sklearn-style estimator (predict / predict_proba)
    classes: list[str]  # label order matching predict_proba columns
    algo: str  # "rf" | "xgb"
    model_version: str
    feature_names: tuple[str, ...] = FEATURE_NAMES
    metrics: dict = field(default_factory=dict)

    # --- inference ---------------------------------------------------------
    def _row(self, features: dict) -> list[list[float]]:
        return rows_to_matrix([features])

    def predict(self, features: dict) -> tuple[str, float]:
        """(predicted class, confidence) where confidence is the winning
        softmax / vote probability."""
        proba = self.predict_proba(features)
        label = max(proba, key=proba.get)
        return label, round(proba[label], 4)

    def predict_proba(self, features: dict) -> dict[str, float]:
        probs = self.model.predict_proba(self._row(features))[0]
        return {cls: float(p) for cls, p in zip(self.classes, probs, strict=False)}

    def feature_importances(self) -> dict[str, float]:
        imp = getattr(self.model, "feature_importances_", None)
        if imp is None:
            return {}
        return {n: round(float(v), 5) for n, v in zip(self.feature_names, imp, strict=False)}

    # --- persistence -----------------------------------------------------
    def save(self, path: str | Path = _DEFAULT_PATH) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "classes": self.classes,
                "algo": self.algo,
                "model_version": self.model_version,
                "feature_names": list(self.feature_names),
                "metrics": self.metrics,
            },
            path,
        )
        return path

    @classmethod
    def load(cls, path: str | Path = _DEFAULT_PATH) -> TrafficClassifier:
        blob = joblib.load(Path(path))
        return cls(
            model=blob["model"],
            classes=list(blob["classes"]),
            algo=blob["algo"],
            model_version=blob["model_version"],
            feature_names=tuple(blob.get("feature_names", FEATURE_NAMES)),
            metrics=blob.get("metrics", {}),
        )

    # --- training ------------------------------------------------------
    @classmethod
    def train(
        cls,
        x_rows: list[dict],
        y: list[str],
        *,
        algo: str = "auto",
        seed: int = 0,
        model_version: str = "dev",
        eval_x: list[dict] | None = None,
        eval_y: list[str] | None = None,
    ) -> TrafficClassifier:
        """Fit RF and/or XGB. ``algo="auto"`` keeps whichever scores the higher
        macro-F1 on (eval_x, eval_y), or on the training data if no eval split
        is given."""
        from sklearn.metrics import f1_score

        candidates = ["rf", "xgb"] if algo == "auto" else [algo]
        vx = eval_x if eval_x is not None else x_rows
        vy = eval_y if eval_y is not None else y

        best: TrafficClassifier | None = None
        best_f1 = -1.0
        for name in candidates:
            clf = cls._fit_one(name, x_rows, y, seed=seed, model_version=model_version)
            preds = [clf.predict(row)[0] for row in vx]
            macro = f1_score(vy, preds, average="macro", zero_division=0)
            if macro > best_f1:
                best, best_f1 = clf, macro
        assert best is not None
        best.metrics = {"selection_macro_f1": round(float(best_f1), 4)}
        return best

    @staticmethod
    def _fit_one(
        name: str, x_rows: list[dict], y: list[str], *, seed: int, model_version: str
    ) -> TrafficClassifier:
        classes = sorted(set(y))
        x_mat = rows_to_matrix(x_rows)

        if name == "rf":
            from sklearn.ensemble import RandomForestClassifier

            model = RandomForestClassifier(
                n_estimators=150,
                max_depth=16,
                class_weight="balanced",
                random_state=seed,
                n_jobs=-1,
            )
            model.fit(x_mat, y)
            return TrafficClassifier(
                model=model,
                classes=list(model.classes_),
                algo="rf",
                model_version=f"{model_version}-rf",
            )

        if name == "xgb":
            import numpy as np
            from xgboost import XGBClassifier

            idx = {c: i for i, c in enumerate(classes)}
            y_enc = np.array([idx[v] for v in y])
            model = XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.9,
                colsample_bytree=0.9,
                random_state=seed,
                tree_method="hist",
                objective="multi:softprob",
                num_class=len(classes),
            )
            model.fit(np.array(x_mat), y_enc)
            return TrafficClassifier(
                model=_XGBWrapper(model, classes),
                classes=classes,
                algo="xgb",
                model_version=f"{model_version}-xgb",
            )

        raise ValueError(f"unknown algo {name!r}")


class _XGBWrapper:
    """Give XGBClassifier the sklearn string-label predict_proba interface."""

    def __init__(self, model, classes: list[str]):
        self._model = model
        self._classes = classes
        self.feature_importances_ = getattr(model, "feature_importances_", None)

    def predict_proba(self, x):
        import numpy as np

        return self._model.predict_proba(np.asarray(x))
