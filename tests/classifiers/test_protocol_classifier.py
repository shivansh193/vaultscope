"""P2-T9 - Stage 4a protocol/crypto classifier.

Acceptance (spec Section 9): given a truncated IKE capture the classifier
recovers encryption / D-H group and stamps confidence_source="classifier".
"""

from __future__ import annotations

import _build as B
import pytest

from core.classifiers import predict_ike_params
from core.classifiers.protocol import _STRUCT_FEATURES, ProtocolClassifier, structural_features
from core.ike_parser import decode_message


@pytest.fixture(scope="module")
def clf() -> ProtocolClassifier:
    return ProtocolClassifier.train(n=2500, seed=0)


def _messages(preset: str, *, truncate: int | None = None):
    req = B.sa_init_for_preset(preset)[0]
    if truncate is not None:
        req = req[:truncate]
    try:
        return [decode_message(req)]
    except Exception:
        # hard truncation: rebuild a minimal message the decoder still frames
        return [decode_message(B.sa_init_for_preset(preset)[0][:60])]


def test_structural_features_shape():
    feats = structural_features(_messages("aes256gcm_ecp521_pfs"))
    assert set(feats) == set(_STRUCT_FEATURES)
    assert feats["has_ke"] == 1.0
    assert feats["ke_data_len"] > 0


@pytest.mark.parametrize(
    "preset,expected_dh",
    [
        ("aes256gcm_ecp521_pfs", "ECP521"),
        ("aes128cbc_sha256_modp2048", "MODP2048"),
        ("3des_sha1_modp1024", "MODP1024"),
    ],
)
def test_dh_group_recovered_from_full_message(clf, preset, expected_dh):
    out = clf.predict(structural_features(_messages(preset)))
    assert out["dh_group"] == expected_dh
    assert out["confidence_source"] == "classifier"


def test_encryption_family_recovered(clf):
    aead = clf.predict(structural_features(_messages("aes256gcm_ecp521_pfs")))["encryption"]
    cbc = clf.predict(structural_features(_messages("aes128cbc_sha256_modp2048")))["encryption"]
    assert "GCM" in aead
    assert cbc.startswith("AES-") and "CBC" in cbc


def test_dh_group_recovered_from_truncated_message(clf):
    # cut the SA_INIT after the KE payload -- SA transforms gone, KE size intact
    msgs = _messages("aes128cbc_sha256_modp2048", truncate=28 + 60 + 4 + 260)
    out = clf.predict(structural_features(msgs))
    assert out["dh_group"] == "MODP2048"  # KE data length still fingerprints it


def test_predict_ike_params_when_untrained(monkeypatch):
    import core.classifiers as cc

    cc._protocol_model.cache_clear()
    monkeypatch.setattr(
        cc.ProtocolClassifier,
        "load",
        staticmethod(lambda *_a, **_k: (_ for _ in ()).throw(FileNotFoundError)),
    )
    assert predict_ike_params(_messages("aes256gcm_ecp521_pfs")) is None
    cc._protocol_model.cache_clear()


def test_save_load_round_trip(tmp_path, clf):
    p = clf.save(tmp_path / "pc.pkl")
    again = ProtocolClassifier.load(p)
    feats = structural_features(_messages("aes256gcm_ecp521_pfs"))
    assert again.predict(feats)["dh_group"] == clf.predict(feats)["dh_group"]


def test_shipped_protocol_model_if_present():
    from pathlib import Path

    if not (Path(__file__).resolve().parents[2] / "models" / "protocol_classifier.pkl").exists():
        pytest.skip("run `python -m core.classifiers.train`")
    out = predict_ike_params(_messages("aes128cbc_sha256_modp2048"))
    assert out is not None and out["confidence_source"] == "classifier"
    assert out["dh_group"] == "MODP2048"
