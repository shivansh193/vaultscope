"""Pipeline wiring and the Block A seam (P3-T9).

The point of these tests is that P3 keeps working whether or not Block A
exists, and that a fixture-mode result is never mistaken for a real decode.

Block A's Stage 2 entry points return a canonical ``VPNSession`` with the
``ike`` block already filled, so the fakes here return the same shape -- the
pipeline's job is to add Stage 3/4b/4c on top, not to reshape the record.
"""

import sys
import types

import pytest

from core import pipeline
from core.models import IkeParams, VPNSession


@pytest.fixture
def fake_parser(monkeypatch):
    """Install a stand-in for Block A's Stage 2 parser."""

    def parsed(session_id, src="10.1.1.1", dst="10.1.1.2", **ike) -> VPNSession:
        return VPNSession(
            session_id=session_id,
            initiator_ip=src,
            responder_ip=dst,
            ike=IkeParams(**ike),
        )

    def install(sessions):
        module = types.ModuleType("core.ike_parser")
        module.parse_ikev2_sessions = lambda source: sessions
        module.parse_ikev1_sessions = lambda source: []
        monkeypatch.setitem(sys.modules, "core.ike_parser", module)

    install.parsed = parsed
    return install


def test_fixture_mode_when_parser_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_load", lambda module, attr: None)
    sessions = pipeline.analyze_capture(tmp_path / "any.pcap")
    assert sessions, "fixture mode must still yield sessions so the API works"


def test_fixture_sessions_are_marked_as_incomplete(monkeypatch, tmp_path):
    """A fixture session must be self-identifying -- never passed off as real."""
    monkeypatch.setattr(pipeline, "_load", lambda module, attr: None)
    for session in pipeline.analyze_capture(tmp_path / "any.pcap"):
        assert session.ike.capture_complete is False
        assert session.traffic_prediction.model_version == "fixture"


def test_parser_available_reflects_block_a(monkeypatch):
    monkeypatch.setattr(pipeline, "_load", lambda module, attr: None)
    assert pipeline.parser_available() is False
    monkeypatch.setattr(pipeline, "_load", lambda module, attr: (lambda source: []))
    assert pipeline.parser_available() is True


def test_both_ike_versions_are_parsed(monkeypatch, tmp_path):
    """A v1-only capture must not be lost because the v2 parser ran first."""
    module = types.ModuleType("core.ike_parser")
    module.parse_ikev2_sessions = lambda source: []
    module.parse_ikev1_sessions = lambda source: [VPNSession(session_id="v1-sa")]
    monkeypatch.setitem(sys.modules, "core.ike_parser", module)

    sessions = pipeline.analyze_capture(tmp_path / "v1.pcap")
    assert [s.session_id for s in sessions] == ["v1-sa"]


def test_one_broken_version_parser_does_not_lose_the_other(monkeypatch, tmp_path):
    def explode(source):
        raise ValueError("malformed IKEv2")

    module = types.ModuleType("core.ike_parser")
    module.parse_ikev2_sessions = explode
    module.parse_ikev1_sessions = lambda source: [VPNSession(session_id="v1-sa")]
    monkeypatch.setitem(sys.modules, "core.ike_parser", module)

    assert [s.session_id for s in pipeline.analyze_capture(tmp_path / "x.pcap")] == ["v1-sa"]


def test_parsed_session_is_assessed(fake_parser, tmp_path):
    fake_parser(
        [
            fake_parser.parsed(
                "spi-a-spi-b",
                version="IKEv1",
                aggressive_mode=True,
                auth_method="PSK",
                encryption="3DES-CBC",
                integrity="HMAC-SHA1",
                dh_group="MODP1024",
                pfs_status="disabled",
                sa_lifetime_sec=90000,
                vendor="Cisco ASA",
            )
        ]
    )
    sessions = pipeline.analyze_capture(tmp_path / "real.pcap")
    assert len(sessions) == 1
    session = sessions[0]
    assert session.session_id == "spi-a-spi-b"
    assert session.initiator_ip == "10.1.1.1"
    assert session.ike.encryption == "3DES-CBC"
    # Stage 4c ran on the parser's own record
    assert "R06" in session.security_assessment.triggered_rules
    assert session.security_assessment.overall_severity == "CRITICAL"


def test_partial_decode_flag_survives_the_pipeline(fake_parser, tmp_path):
    """Block A flags a partial decode; nothing downstream may quietly clear it."""
    fake_parser([fake_parser.parsed("partial", version="IKEv2", capture_complete=False)])
    assert pipeline.analyze_capture(tmp_path / "partial.pcap")[0].ike.capture_complete is False


def test_capture_metadata_is_stamped(fake_parser, tmp_path):
    fake_parser([fake_parser.parsed("s1", version="IKEv2")])
    capture = tmp_path / "my_capture.pcap"
    session = pipeline.analyze_capture(capture, source="live_nic")[0]
    assert session.capture_file == "my_capture.pcap"
    assert session.capture_source == "live_nic"


def test_assessment_always_runs(fake_parser, tmp_path):
    fake_parser([fake_parser.parsed("s1", version="IKEv2", dh_group="MODP768")])
    session = pipeline.analyze_capture(tmp_path / "x.pcap")[0]
    assert "R03" in session.security_assessment.triggered_rules
    assert session.security_assessment.findings[0].remediation


def test_broken_flow_extractor_does_not_sink_the_capture(fake_parser, monkeypatch, tmp_path):
    """A half-built Block A stage must degrade, not crash the whole analysis."""

    def exploding(module, attr):
        if attr == "parse_ikev2_sessions":
            return lambda source: [fake_parser.parsed("s1", version="IKEv2")]
        if attr == "parse_ikev1_sessions":
            return lambda source: []
        if attr == "extract_features":
            return lambda source: (_ for _ in ()).throw(RuntimeError("half-built"))
        return None

    monkeypatch.setattr(pipeline, "_load", exploding)
    sessions = pipeline.analyze_capture(tmp_path / "x.pcap")
    assert len(sessions) == 1
    assert sessions[0].flow_features.pkt_total == 0


def test_empty_parse_yields_no_sessions(fake_parser, tmp_path):
    fake_parser([])
    assert pipeline.analyze_capture(tmp_path / "empty.pcap") == []
