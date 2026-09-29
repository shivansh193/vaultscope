"""RFC 9370 / ML-KEM detection feeding pqc_status (and rule R20)."""

import _build as B

from core.ike_parser import parse_ikev2_sessions
from core.ike_parser._transforms import TRANSFORM_TYPE_DH, pqc_status
from core.ike_parser._wire import Proposal, Transform
from core.ike_parser.ikev2 import _apply_ike_proposal


def test_classical_sa_init_reads_classical():
    (session,) = parse_ikev2_sessions(B.sa_init_pair(12, 5, 12, 19, keylen=256))
    assert session.ike.pqc_status == "classical"
    assert session.ike.additional_key_exchanges == []


def test_addke_transform_is_hybrid():
    ike: dict = {}
    prop = Proposal(1, 1, b"", [Transform(TRANSFORM_TYPE_DH, 19), Transform(6, 36)])
    _apply_ike_proposal(ike, prop)
    assert ike["additional_key_exchanges"] == ["ML-KEM-768"]
    assert pqc_status(ike["dh_group"], ike["additional_key_exchanges"]) == "hybrid"


def test_addke_none_is_not_hybrid():
    ike: dict = {}
    _apply_ike_proposal(
        ike, Proposal(1, 1, b"", [Transform(TRANSFORM_TYPE_DH, 19), Transform(6, 0)])
    )
    assert pqc_status(ike["dh_group"], ike["additional_key_exchanges"]) == "classical"


def test_unknown_group_is_unknown():
    assert pqc_status("unknown", []) == "unknown"
    assert pqc_status("ML-KEM-1024", []) == "hybrid"
