"""Stage 4a - Protocol / Crypto Classifier (P2-T9).

The deterministic IKE parser (Stage 2) already declares the negotiated crypto
in cleartext for a complete handshake. This RF fallback covers the ~10% the
spec calls out: truncated captures, vendor extensions, malformed payloads --
cases where ``VPNSession.ike.capture_complete`` is False and a field is still
at its model default.

Signal: IKE message *structure*, not decoded transforms. The KE payload's key
data length is essentially a fingerprint of the D-H group (MODP2048 -> 256 B,
ECP256 -> 64 B, ...), and the whole SA_INIT message size shifts measurably with
the cipher (AES adds a Key Length attribute, GCM drops the INTEG transform).

Output carries ``confidence_source = "classifier"`` so a consumer never
mistakes a guessed field for a parsed one.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path

import joblib

# canonical D-H public-value sizes in bytes -- the strongest structural signal
_DH_KEY_BYTES: dict[str, int] = {
    "MODP768": 96,
    "MODP1024": 128,
    "MODP1536": 192,
    "MODP2048": 256,
    "MODP3072": 384,
    "MODP4096": 512,
    "ECP256": 64,
    "ECP384": 96,
    "ECP521": 132,
    "Curve25519": 32,
}

_STRUCT_FEATURES: tuple[str, ...] = (
    "sa_init_bytes",
    "ke_data_len",
    "n_payloads",
    "n_transforms",
    "has_ke",
    "has_nonce",
    "has_natd",
    "aead_hint",  # SA payload short for its transform count -> AEAD (no INTEG)
    "keylen_attr",  # AES Key Length attribute value in bits, 0 if not readable
)

_DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "protocol_classifier.pkl"

# (encryption, key_length or None) options the synthetic trainer covers.
_ENCR_OPTIONS: tuple[tuple[str, int | None, bool], ...] = (
    ("AES-256-GCM", 256, True),
    ("AES-128-GCM", 128, True),
    ("AES-256-CBC", 256, False),
    ("AES-128-CBC", 128, False),
    ("3DES-CBC", None, False),
    ("DES-CBC", None, False),
)
_DH_OPTIONS = ("MODP1024", "MODP1536", "MODP2048", "ECP256", "ECP384", "ECP521")


def structural_features(messages) -> dict[str, float]:
    """Structural feature vector from whatever survived of an IKE_SA_INIT."""
    from core.ike_parser._transforms import (
        PAYLOAD_KE,
        PAYLOAD_NONCE,
        PAYLOAD_NOTIFY,
        PAYLOAD_SA,
    )

    sa_init = [m for m in messages if m.exchange_type == 34] or list(messages)
    if not sa_init:
        return dict.fromkeys(_STRUCT_FEATURES, 0.0)
    m = sa_init[0]
    payloads = list(m.payloads)
    ke = next((p for p in payloads if p.type == PAYLOAD_KE), None)
    sa = next((p for p in payloads if p.type == PAYLOAD_SA), None)
    transforms = sa.proposals[0].transforms if (sa and sa.proposals) else []
    n_transforms = len(transforms)
    # an AEAD suite (AES-GCM/CCM, ChaCha20) negotiates no INTEG transform (type 3)
    aead_hint = 1.0 if (transforms and not any(t.type == 3 for t in transforms)) else 0.0
    keylen_attr = next((t.key_length for t in transforms if t.key_length), 0)

    return {
        "sa_init_bytes": float(m.length or sum(4 + len(p.raw) for p in payloads) + 28),
        "ke_data_len": float(len(ke.raw) - 4 if ke and len(ke.raw) > 4 else 0),
        "n_payloads": float(len(payloads)),
        "n_transforms": float(n_transforms),
        "has_ke": 1.0 if ke else 0.0,
        "has_nonce": 1.0 if any(p.type == PAYLOAD_NONCE for p in payloads) else 0.0,
        "has_natd": 1.0 if any(p.type == PAYLOAD_NOTIFY for p in payloads) else 0.0,
        "aead_hint": aead_hint,
        "keylen_attr": float(keylen_attr or 0),
    }


def _row(feat: dict[str, float]) -> list[float]:
    return [float(feat.get(k, 0.0)) for k in _STRUCT_FEATURES]


@dataclass
class ProtocolClassifier:
    encr_model: object
    dh_model: object
    model_version: str = "dev"
    metrics: dict = field(default_factory=dict)

    def predict(self, features: dict[str, float]) -> dict:
        x = [_row(features)]
        encr_p = self.encr_model.predict_proba(x)[0]
        dh_p = self.dh_model.predict_proba(x)[0]
        ei = int(encr_p.argmax())
        di = int(dh_p.argmax())
        return {
            "encryption": list(self.encr_model.classes_)[ei],
            "dh_group": list(self.dh_model.classes_)[di],
            "confidence": round(float(min(encr_p[ei], dh_p[di])), 4),
            "confidence_source": "classifier",
        }

    def save(self, path: str | Path = _DEFAULT_PATH) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "encr_model": self.encr_model,
                "dh_model": self.dh_model,
                "model_version": self.model_version,
                "metrics": self.metrics,
            },
            path,
        )
        return path

    @classmethod
    def load(cls, path: str | Path = _DEFAULT_PATH) -> ProtocolClassifier:
        b = joblib.load(Path(path))
        return cls(b["encr_model"], b["dh_model"], b["model_version"], b.get("metrics", {}))

    @classmethod
    def train(
        cls, *, n: int = 400, seed: int = 0, model_version: str = "synthetic"
    ) -> ProtocolClassifier:
        from sklearn.ensemble import RandomForestClassifier

        x, y_encr, y_dh = _synth_table(n, seed=seed)
        encr = RandomForestClassifier(n_estimators=50, max_depth=9, random_state=seed).fit(
            x, y_encr
        )
        dh = RandomForestClassifier(n_estimators=50, max_depth=9, random_state=seed).fit(x, y_dh)
        return cls(encr, dh, model_version=model_version)


def _synth_table(n: int, *, seed: int) -> tuple[list[list[float]], list[str], list[str]]:
    """Synthesize structural feature rows for known configs, including partial
    captures (SA payload dropped, KE truncated, message cut short)."""
    rng = random.Random(seed)
    x: list[list[float]] = []
    y_encr: list[str] = []
    y_dh: list[str] = []
    for _ in range(n):
        encr, keylen, aead = rng.choice(_ENCR_OPTIONS)
        dh = rng.choice(_DH_OPTIONS)
        ke_len = _DH_KEY_BYTES[dh]
        n_tf = 3 if aead else 4
        # base SA_INIT: hdr 28 + SA (~8 + n_tf*8 + keylen attr) + KE (8 + ke_len)
        sa_bytes = 8 + n_tf * 8 + (4 if keylen else 0) + rng.randint(-2, 6)
        full = 28 + (4 + sa_bytes) + (8 + ke_len) + (4 + 32) + rng.randint(0, 60)

        truncation = rng.choice((1.0, 1.0, 1.0, rng.uniform(0.4, 0.9)))
        partial = truncation < 1.0
        sa_survived = (not partial) or rng.random() > 0.5
        feat = {
            "sa_init_bytes": full * truncation + rng.uniform(-8, 8),
            "ke_data_len": ke_len if (not partial or rng.random() > 0.4) else ke_len * truncation,
            "n_payloads": rng.choice((4, 5)) if not partial else rng.choice((1, 2, 3)),
            "n_transforms": n_tf if (not partial or rng.random() > 0.5) else rng.choice((0, 1, 2)),
            "has_ke": 1.0 if (not partial or rng.random() > 0.3) else 0.0,
            "has_nonce": 1.0 if not partial else float(rng.random() > 0.5),
            "has_natd": float(rng.random() > 0.4),
            "aead_hint": 1.0 if aead else 0.0,
            # Key Length attribute is readable only when the SA payload survived
            "keylen_attr": float(keylen or 0) if sa_survived else 0.0,
        }
        if not sa_survived:
            feat["n_transforms"] = 0.0
            feat["aead_hint"] = 0.0
        x.append(_row(feat))
        y_encr.append(encr)
        y_dh.append(dh)
    return x, y_encr, y_dh
