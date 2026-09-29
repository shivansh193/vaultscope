"""Held-out evaluation of Stage 4b, and the tunnel/transport mode model.

    python -m core.classifiers.heldout            # writes models/heldout_eval.json
    python -m core.classifiers.heldout --save-mode-model

The headline 0.98 macro-F1 in eval_metrics.json comes from one random 70/15/15
split. A random split lets near-identical captures of the same configuration
land on both sides, so it says little about a configuration the model has never
seen. Here every scheme holds out whole groups instead -- every capture of one
cipher suite, one DH group, one mode, one IP version, or one exact
configuration -- trains on the rest and scores the held-out part.

The ablation reruns everything without the three volume features (pkt_total,
rate_pps, flow_duration_sec). Each capture runs one generator at a fixed rate
for a fixed 30 s, so volume alone can name the class; the ablation shows how
much of the score is that shortcut.

The second half does the same for ESP mode. IKEv2 negotiates mode inside the
encrypted IKE_AUTH, so the parser reads "unknown" on every capture. Tunnel mode
wraps an extra inner IP header (20 bytes IPv4, 40 bytes IPv6) into every ESP
packet; the mode model tries to see that in the size statistics.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

from core.flow.features import FEATURE_NAMES

from .dataset import pcap_table_with_labels

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
VOLUME_FEATURES = ("pkt_total", "rate_pps", "flow_duration_sec")

# Group key per scheme, read off a ground-truth label.
SCHEMES = {
    "leave_one_cipher_out": lambda lab: lab["config"]["encryption"],
    "leave_one_dh_group_out": lambda lab: lab["config"]["dh_group"],
    "leave_one_mode_out": lambda lab: lab["config"]["mode"],
    "leave_one_ip_version_out": lambda lab: lab["config"]["ip_version"],
    "group_5fold_by_config": lambda lab: lab["stem"].split("__")[0],
}


def _rf(seed: int = 0):
    from sklearn.ensemble import RandomForestClassifier

    # Same family and settings as the shipped Stage 4b RF.
    return RandomForestClassifier(
        n_estimators=150, max_depth=16, class_weight="balanced", random_state=seed, n_jobs=-1
    )


def _matrix(rows: list[dict], names: list[str]) -> list[list[float]]:
    return [[float(r.get(n, 0.0)) for n in names] for r in rows]


def _folds(groups: list[str], scheme: str, seed: int):
    """(train_idx, test_idx, held-out group name) per fold."""
    idx = list(range(len(groups)))
    if scheme == "group_5fold_by_config":
        from sklearn.model_selection import GroupKFold

        for k, (tr, te) in enumerate(GroupKFold(n_splits=5).split(idx, groups=groups)):
            yield list(tr), list(te), f"fold{k + 1}"
    else:
        for g in sorted(set(groups)):
            yield [i for i in idx if groups[i] != g], [i for i in idx if groups[i] == g], g


def _score(y_true, y_pred, labels) -> dict:
    from sklearn.metrics import accuracy_score, f1_score

    return {
        "n": len(y_true),
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "f1_macro": round(
            f1_score(y_true, y_pred, labels=sorted(set(y_true)), average="macro", zero_division=0),
            4,
        ),
    }


def evaluate(
    x: list[list[float]], y: list[str], labels: list[dict], *, seed: int = 0, extra=None
) -> dict:
    """Every scheme on one feature matrix. ``extra`` adds more group schemes."""
    from sklearn.model_selection import StratifiedKFold

    classes = sorted(set(y))
    out: dict = {}

    pred = [None] * len(y)
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=seed).split(x, y):
        model = _rf(seed).fit([x[i] for i in tr], [y[i] for i in tr])
        for i, p in zip(te, model.predict([x[i] for i in te]), strict=True):
            pred[i] = p
    out["random_stratified_5fold"] = {"pooled": _score(y, pred, classes)}

    for scheme, key in {**SCHEMES, **(extra or {})}.items():
        groups = [key(lab) for lab in labels]
        pred = [None] * len(y)
        per_group = {}
        for tr, te, name in _folds(groups, scheme, seed):
            if len({y[i] for i in tr}) < 2:
                continue
            model = _rf(seed).fit([x[i] for i in tr], [y[i] for i in tr])
            got = list(model.predict([x[i] for i in te]))
            for i, p in zip(te, got, strict=True):
                pred[i] = p
            per_group[name] = _score([y[i] for i in te], got, classes)
        scored = [i for i, p in enumerate(pred) if p is not None]
        out[scheme] = {
            "pooled": _score([y[i] for i in scored], [pred[i] for i in scored], classes),
            "per_held_out_group": per_group,
        }
    return out


def _confusions(y, pred) -> list[str]:
    pairs: dict[tuple[str, str], int] = defaultdict(int)
    for t, p in zip(y, pred, strict=True):
        if t != p:
            pairs[(t, p)] += 1
    return [f"{t} -> {p}: {n}" for (t, p), n in sorted(pairs.items(), key=lambda kv: -kv[1])]


# --- mode ------------------------------------------------------------------
def mode_features(flow: dict, ip_version: str, encryption: str) -> dict:
    """Flow statistics plus what the IKE handshake already told us in cleartext."""
    enc = encryption.upper()
    return {
        **{n: float(flow.get(n, 0.0)) for n in FEATURE_NAMES},
        "is_ipv6": 1.0 if ip_version == "IPv6" else 0.0,
        "is_aead": 1.0 if "GCM" in enc or "CCM" in enc else 0.0,
        "block_8": 1.0 if "DES" in enc else 0.0,
    }


MODE_FEATURES = [*FEATURE_NAMES, "is_ipv6", "is_aead", "block_8"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=MODELS_DIR)
    ap.add_argument(
        "--save-mode-model",
        action="store_true",
        help="fit the mode model on every capture and write models/mode_classifier.pkl",
    )
    args = ap.parse_args(argv)

    rows, labels = pcap_table_with_labels()
    if not rows:
        print("no captures in data/pcaps -- run scripts/generate_dataset.py --from-labels")
        return 2
    y = [lab["traffic_class"] for lab in labels]
    print(f"{len(rows)} captures")

    all_names = list(FEATURE_NAMES)
    ablated = [n for n in all_names if n not in VOLUME_FEATURES]
    traffic = {
        "all_features": evaluate(_matrix(rows, all_names), y, labels, seed=args.seed),
        "without_volume_features": evaluate(_matrix(rows, ablated), y, labels, seed=args.seed),
    }

    # Where the held-out-config errors land, for the write-up.
    from sklearn.model_selection import GroupKFold

    x = _matrix(rows, all_names)
    groups = [lab["stem"].split("__")[0] for lab in labels]
    pred = [None] * len(y)
    for tr, te in GroupKFold(5).split(x, groups=groups):
        model = _rf(args.seed).fit([x[i] for i in tr], [y[i] for i in tr])
        for i, p in zip(te, model.predict([x[i] for i in te]), strict=True):
            pred[i] = p
    traffic["group_5fold_by_config_confusions"] = _confusions(y, pred)

    mode_x = _matrix(
        [
            mode_features(r, lab["config"]["ip_version"], lab["config"]["encryption"])
            for r, lab in zip(rows, labels, strict=True)
        ],
        MODE_FEATURES,
    )
    mode_y = [lab["config"]["mode"] for lab in labels]
    mode = evaluate(
        mode_x,
        mode_y,
        labels,
        seed=args.seed,
        extra={"leave_one_traffic_class_out": lambda lab: lab["traffic_class"]},
    )
    mode.pop("leave_one_mode_out")  # holding out a whole target class is meaningless

    result = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "n_captures": len(rows),
        "model": "RandomForest(150 trees, depth 16, balanced) -- the shipped Stage 4b family",
        "traffic_type": traffic,
        "mode_inference": mode,
        "note": (
            "Each scheme holds out every capture sharing the named property, trains on the "
            "rest, and scores the held-out part. 'pooled' concatenates all held-out "
            "predictions. The dataset is lab-clean, one class per capture."
        ),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "heldout_eval.json").write_text(json.dumps(result, indent=2) + "\n")

    for part, res in (("traffic", traffic["all_features"]), ("mode", mode)):
        for scheme, r in res.items():
            print(f"{part:8s} {scheme:28s} macro-F1 {r['pooled']['f1_macro']}")
    for scheme, r in traffic["without_volume_features"].items():
        print(f"ablated  {scheme:28s} macro-F1 {r['pooled']['f1_macro']}")

    if args.save_mode_model:
        import joblib

        model = _rf(args.seed).fit(mode_x, mode_y)
        joblib.dump(
            {
                "model": model,
                "feature_names": MODE_FEATURES,
                "heldout_f1_macro": mode["group_5fold_by_config"]["pooled"]["f1_macro"],
            },
            args.out / "mode_classifier.pkl",
        )
        print(f"wrote {args.out / 'mode_classifier.pkl'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
