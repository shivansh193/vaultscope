"""JSON + CEF machine export (spec Section 9, P3-T6)."""

import json
import re

from core.models import VPNSession
from reporting import export


def test_json_matches_data_model_schema(sessions):
    """Spec done-criteria: JSON matches the Section 5 data model."""
    payload = json.loads(export.to_json(sessions))
    assert len(payload) == len(sessions)
    for record in payload:
        assert set(record) >= {
            "session_id",
            "capture_source",
            "timestamp",
            "initiator_ip",
            "responder_ip",
            "ike",
            "flow_features",
            "traffic_prediction",
            "security_assessment",
            "reports",
        }
    # round-trips back into the model without loss
    assert [VPNSession(**r) for r in payload] == sessions


def test_json_written_to_disk(sessions, tmp_path):
    path = export.write_json(sessions, tmp_path / "out" / "sessions.json")
    assert json.loads(path.read_text())[0]["session_id"] == sessions[0].session_id


CEF_HEADER = re.compile(
    r"^CEF:0\|VaultScope\|IPsec Analyzer\|1\.0\|(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>\d+)\|"
)


def test_cef_header_validates_against_spec(sessions):
    for line in export.to_cef(sessions).splitlines():
        match = CEF_HEADER.match(line)
        assert match, f"malformed CEF header: {line}"
        assert 0 <= int(match.group("sev")) <= 10


def test_cef_emits_one_event_per_finding(weak_session):
    lines = export.to_cef([weak_session]).splitlines()
    assert len(lines) == len(weak_session.security_assessment.findings)
    signatures = {CEF_HEADER.match(x).group("sig") for x in lines}
    assert signatures == set(weak_session.security_assessment.triggered_rules)


def test_cef_emits_an_event_for_clean_sessions(clean_session):
    """A clean tunnel must still reach the SIEM, or it looks unassessed."""
    lines = export.to_cef([clean_session]).splitlines()
    assert len(lines) == 1
    assert CEF_HEADER.match(lines[0]).group("sig") == "VS-CLEAN"
    assert lines[0].endswith("rt=2026-09-05T10:05:00Z") or "rt=" in lines[0]


def test_cef_severity_maps_from_our_scale(weak_session):
    critical = [
        line
        for line in export.to_cef([weak_session]).splitlines()
        if CEF_HEADER.match(line).group("sig") in {"R04", "R06"}
    ]
    assert critical
    for line in critical:
        assert CEF_HEADER.match(line).group("sev") == "10"


def test_cef_carries_session_context(weak_session):
    line = export.to_cef([weak_session]).splitlines()[0]
    assert f"src={weak_session.initiator_ip}" in line
    assert f"dst={weak_session.responder_ip}" in line
    assert f"cs1={weak_session.session_id}" in line
    assert "cn1=" in line


def test_cef_escapes_pipe_and_equals(clean_session):
    """Unescaped '|' would terminate a header field early and corrupt the event."""
    clean_session.ike.vendor = "Acme|Corp"
    clean_session.session_id = "sess=weird|id"
    line = export.to_cef([clean_session]).splitlines()[0]
    assert CEF_HEADER.match(line), line
    assert "cs1=sess\\=weird|id" in line


def test_cef_has_no_embedded_newlines(weak_session):
    """Remediation text is multi-line; a raw newline would split one event
    into several malformed ones."""
    lines = export.to_cef([weak_session]).splitlines()
    assert len(lines) == len(weak_session.security_assessment.findings)


def test_cef_written_to_disk(sessions, tmp_path):
    path = export.write_cef(sessions, tmp_path / "out" / "sessions.cef")
    assert path.read_text().startswith("CEF:0|")


def test_empty_fleet_exports_cleanly():
    assert json.loads(export.to_json([])) == []
    assert export.to_cef([]) == ""
