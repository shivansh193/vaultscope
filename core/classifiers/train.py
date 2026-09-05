"""Train the Stage 4b traffic classifier and write the judge-facing artifacts.

    python -m core.classifiers.train              # pcap dataset if present, else synthetic
    python -m core.classifiers.train --synthetic  # force the bootstrap set
    python -m core.classifiers.train --n 250      # synthetic flows per class

Writes to ``models/``:
    traffic_classifier.pkl   the selected model (RF or XGB)
    eval_metrics.json        per-class precision/recall/F1, macro-F1, accuracy
    confusion_matrix.json    labels + matrix on the held-out test split
    feature_importance.png   RF importances (spec deliverable, judge demo)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from .dataset import load_table, rows_to_matrix
from .traffic import TrafficClassifier

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"


def _split(x, y, *, seed=0):
    """Stratified 70 / 15 / 15 train / val / test."""
    from sklearn.model_selection import train_test_split

    x_tr, x_tmp, y_tr, y_tmp = train_test_split(x, y, test_size=0.30, random_state=seed, stratify=y)
    x_val, x_te, y_val, y_te = train_test_split(
        x_tmp, y_tmp, test_size=0.50, random_state=seed, stratify=y_tmp
    )
    return (x_tr, y_tr), (x_val, y_val), (x_te, y_te)


def _write_feature_importance_png(clf: TrafficClassifier, path: Path) -> None:
    imp = clf.feature_importances()
    if not imp:
        return
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    items = sorted(imp.items(), key=lambda kv: kv[1])
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh([k for k, _ in items], [v for _, v in items], color="#4c72b0")
    ax.set_title(f"Stage 4b feature importance ({clf.algo.upper()})")
    ax.set_xlabel("importance")
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--synthetic", action="store_true", help="force the bootstrap flow set")
    ap.add_argument("--n", type=int, default=180, help="synthetic flows per class")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=MODELS_DIR)
    args = ap.parse_args(argv)

    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

    x, y, source = load_table(
        synthetic=True if args.synthetic else None, n_per_class=args.n, seed=args.seed
    )
    print(f"training table: {len(x)} rows from {source}; classes={sorted(set(y))}")

    (x_tr, y_tr), (x_val, y_val), (x_te, y_te) = _split(x, y, seed=args.seed)
    version = f"{source}-{dt.date.today().isoformat()}"
    clf = TrafficClassifier.train(
        x_tr,
        y_tr,
        algo="auto",
        seed=args.seed,
        model_version=version,
        eval_x=x_val,
        eval_y=y_val,
    )
    print(f"selected {clf.algo.upper()}  (val macro-F1 {clf.metrics['selection_macro_f1']})")

    preds = [clf.predict(row)[0] for row in x_te]
    labels = sorted(set(y))
    report = classification_report(y_te, preds, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_te, preds, labels=labels).tolist()

    args.out.mkdir(parents=True, exist_ok=True)
    metrics = {
        "model_version": clf.model_version,
        "algo": clf.algo,
        "source": source,
        "n_train": len(x_tr),
        "n_test": len(x_te),
        "accuracy": round(accuracy_score(y_te, preds), 4),
        "f1_macro": round(report["macro avg"]["f1-score"], 4),
        "per_class": {
            c: {k: round(report[c][k], 4) for k in ("precision", "recall", "f1-score")}
            for c in labels
        },
        "feature_importance": clf.feature_importances(),
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "note": (
            "Bootstrap model trained on synthetic per-class flows; retrain on the "
            "Stage 0 pcap dataset with `python -m core.classifiers.train`."
            if source == "synthetic-bootstrap"
            else "Trained on the captured Stage 0 dataset."
        ),
    }
    (args.out / "eval_metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    # schema consumed by reporting/templates/technical.html.j2 and the dashboard:
    # labels, matrix, accuracy, model_version (see tests/reporting/test_reports.py).
    (args.out / "confusion_matrix.json").write_text(
        json.dumps(
            {
                "labels": labels,
                "matrix": cm,
                "accuracy": metrics["accuracy"],
                "f1_macro": metrics["f1_macro"],
                "model_version": clf.model_version,
            },
            indent=2,
        )
        + "\n"
    )
    clf.save(args.out / "traffic_classifier.pkl")
    _write_feature_importance_png(clf, args.out / "feature_importance.png")

    print(f"accuracy {metrics['accuracy']}  macro-F1 {metrics['f1_macro']}")
    print(f"wrote {args.out}/traffic_classifier.pkl, eval_metrics.json, confusion_matrix.json")
    _ = rows_to_matrix  # re-exported for tests
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
