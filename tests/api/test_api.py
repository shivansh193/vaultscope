"""FastAPI routes + full pipeline wiring (spec Section 9, P3-T7 + P3-T9)."""

import json


def test_post_ingest_returns_session_count(client, test_pcap):
    with test_pcap.open("rb") as fh:
        resp = client.post("/ingest", files={"file": ("ike.pcap", fh)})
    assert resp.status_code == 200
    assert resp.json()["session_count"] >= 1


def test_get_sessions_returns_list(client):
    resp = client.get("/sessions")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_session_record_fully_populated(client, test_pcap):
    with test_pcap.open("rb") as fh:
        client.post("/ingest", files={"file": ("ike.pcap", fh)})
    sessions = client.get("/sessions").json()
    s = sessions[0]
    assert all(k in s for k in ["session_id", "ike", "traffic_prediction", "security_assessment"])
    assert s["ike"]["encryption"] is not None
    assert 0 <= s["security_assessment"]["risk_score"] <= 100


def test_critical_session_has_findings(client, weak_pcap):
    with weak_pcap.open("rb") as fh:
        client.post("/ingest", files={"file": ("weak.pcap", fh)})
    sessions = client.get("/sessions").json()
    critical = [s for s in sessions if s["security_assessment"]["overall_severity"] == "CRITICAL"]
    assert len(critical) >= 1
    assert len(critical[0]["security_assessment"]["findings"]) >= 1
    assert critical[0]["security_assessment"]["findings"][0]["remediation"] != ""


# --- contract coverage beyond the spec's four ------------------------------


def test_health_reports_parser_availability(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["version"]
    assert isinstance(body["parser_available"], bool)


def test_ingest_flags_fixture_mode_honestly(client, test_pcap):
    """Callers must be able to tell a fixture-mode result from a real decode."""
    with test_pcap.open("rb") as fh:
        body = client.post("/ingest", files={"file": ("ike.pcap", fh)}).json()
    health = client.get("/health").json()
    assert body["fixture_mode"] == (not health["parser_available"])


def test_sessions_filter_by_severity(client, ingested):
    critical = client.get("/sessions", params={"severity": "CRITICAL"}).json()
    assert critical
    assert {s["security_assessment"]["overall_severity"] for s in critical} == {"CRITICAL"}


def test_sessions_pagination(client, ingested):
    first = client.get("/sessions", params={"limit": 2, "offset": 0}).json()
    second = client.get("/sessions", params={"limit": 2, "offset": 2}).json()
    assert len(first) == 2
    assert {s["session_id"] for s in first}.isdisjoint({s["session_id"] for s in second})


def test_sessions_rejects_absurd_limit(client):
    assert client.get("/sessions", params={"limit": 100000}).status_code == 422


def test_get_single_session(client, ingested):
    listed = client.get("/sessions").json()[0]
    fetched = client.get(f"/session/{listed['session_id']}").json()
    assert fetched["session_id"] == listed["session_id"]
    assert fetched["ike"] == listed["ike"]


def test_get_unknown_session_is_404(client):
    assert client.get("/session/does-not-exist").status_code == 404


def test_events_endpoint_returns_anomalies(client, ingested):
    events = client.get("/events").json()
    assert isinstance(events, list)
    for event in events:
        assert {"anomaly_id", "session_id", "anomaly_type", "severity"} <= set(event)


def test_events_filter_by_session(client, ingested):
    events = client.get("/events").json()
    if not events:
        return
    target = events[0]["session_id"]
    filtered = client.get("/events", params={"session_id": target}).json()
    assert {e["session_id"] for e in filtered} == {target}


def test_diff_reports_added_removed_degraded(client, test_pcap):
    with test_pcap.open("rb") as fh:
        base = client.post("/ingest", files={"file": ("a.pcap", fh)}).json()["job_id"]
    with test_pcap.open("rb") as fh:
        compare = client.post("/ingest", files={"file": ("b.pcap", fh)}).json()["job_id"]

    body = client.get("/sessions/diff", params={"base_job": base, "compare_job": compare}).json()
    assert set(body) == {"added", "removed", "degraded"}
    # identical captures: nothing appears, disappears or worsens
    assert body["added"] == [] and body["removed"] == [] and body["degraded"] == []


def test_diff_unknown_job_is_404(client, ingested):
    resp = client.get("/sessions/diff", params={"base_job": ingested, "compare_job": "nope"})
    assert resp.status_code == 404


def test_report_generation_all_four_types(client, ingested):
    for report_type in ("executive", "technical", "json", "cef"):
        resp = client.post(f"/report/{ingested}", json={"type": report_type})
        assert resp.status_code == 200, resp.text
        url = resp.json()["download_url"]

        downloaded = client.get(url)
        assert downloaded.status_code == 200
        assert downloaded.content, f"{report_type} report is empty"


def test_report_json_download_is_valid_json(client, ingested):
    url = client.post(f"/report/{ingested}", json={"type": "json"}).json()["download_url"]
    payload = json.loads(client.get(url).content)
    assert isinstance(payload, list) and payload


def test_report_executive_download_is_a_pdf(client, ingested):
    url = client.post(f"/report/{ingested}", json={"type": "executive"}).json()["download_url"]
    assert client.get(url).content.startswith(b"%PDF")


def test_report_rejects_unknown_type(client, ingested):
    assert client.post(f"/report/{ingested}", json={"type": "powerpoint"}).status_code == 422


def test_report_for_unknown_job_is_404(client):
    assert client.post("/report/nope", json={"type": "json"}).status_code == 404


def test_report_download_rejects_path_traversal(client):
    """`filename` is user-controlled; it must not escape the report directory."""
    for attempt in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd"):
        assert client.get(f"/report/download/{attempt}").status_code in (404, 400)


def test_openapi_schema_is_generated(client):
    schema = client.get("/openapi.json").json()
    for route in ("/ingest", "/sessions", "/session/{session_id}", "/events", "/health"):
        assert route in schema["paths"], f"{route} missing from Swagger schema"


def test_websocket_receives_sessions_on_ingest(client, test_pcap):
    """P3-T8: a new session reaches live subscribers without polling."""
    with client.websocket_connect("/ws/live") as ws:
        with test_pcap.open("rb") as fh:
            client.post("/ingest", files={"file": ("ike.pcap", fh)})
        event = ws.receive_json()
        assert "session_id" in event
        assert "security_assessment" in event


def test_ingest_does_not_leak_upload_files(client, test_pcap):
    from api.main import UPLOAD_DIR

    before = set(UPLOAD_DIR.glob("*")) if UPLOAD_DIR.exists() else set()
    with test_pcap.open("rb") as fh:
        client.post("/ingest", files={"file": ("ike.pcap", fh)})
    after = set(UPLOAD_DIR.glob("*")) if UPLOAD_DIR.exists() else set()
    assert after == before, "uploaded capture was not cleaned up"


def test_diff_returns_whole_sessions_not_just_ids(client, test_pcap):
    """A caller comparing captures is about to ask what changed; make them
    re-fetch the records to answer that and the endpoint has done half a job."""
    from api import store
    from core.models import VPNSession

    healthy = VPNSession(session_id="drifting")
    healthy.security_assessment.risk_score = 90
    healthy.security_assessment.overall_severity = "LOW"
    store.save_sessions("job-before", [healthy], capture_file="before.pcap")

    worse = VPNSession(session_id="drifting")
    worse.security_assessment.risk_score = 20
    worse.security_assessment.overall_severity = "CRITICAL"
    gone_and_new = VPNSession(session_id="brand-new")
    store.save_sessions("job-after", [worse, gone_and_new], capture_file="after.pcap")

    body = client.get(
        "/sessions/diff", params={"base_job": "job-before", "compare_job": "job-after"}
    ).json()

    assert [s["session_id"] for s in body["added"]] == ["brand-new"]
    assert body["added"][0]["ike"]["encryption"], "added entries are full session records"
    assert body["removed"] == []

    (degraded,) = body["degraded"]
    assert degraded["session_id"] == "drifting"
    assert (degraded["base_severity"], degraded["compare_severity"]) == ("LOW", "CRITICAL")
    assert (degraded["base_score"], degraded["compare_score"]) == (90, 20)
    # Both whole records travel with it, so the UI can show before and after.
    assert degraded["base"]["security_assessment"]["risk_score"] == 90
    assert degraded["compare"]["security_assessment"]["risk_score"] == 20
