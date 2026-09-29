"""Jobs: one analysed capture each -- listing, summary, evidence, deletion."""

import io


def _upload(client, path, name="ike.pcap"):
    with path.open("rb") as fh:
        return client.post("/ingest", files={"file": (name, fh)})


def test_jobs_are_listed_newest_first(client, test_pcap, weak_pcap):
    first = _upload(client, test_pcap, "first.pcap").json()["job_id"]
    second = _upload(client, weak_pcap, "second.pcap").json()["job_id"]
    listed = client.get("/jobs").json()
    assert [j["job_id"] for j in listed] == [second, first]
    assert listed[0]["capture_file"] == "second.pcap"


def test_job_summary_matches_its_sessions_and_events(client, ingested):
    job = client.get(f"/jobs/{ingested}").json()
    sessions = client.get("/sessions", params={"job_id": ingested}).json()
    events = client.get("/events", params={"job_id": ingested}).json()

    assert job["session_count"] == len(sessions) == 5
    assert sum(job["severity_counts"].values()) == 5
    assert job["severity_counts"]["CRITICAL"] == sum(
        s["security_assessment"]["overall_severity"] == "CRITICAL" for s in sessions
    )
    expected = round(sum(s["security_assessment"]["risk_score"] for s in sessions) / 5)
    assert job["posture_score"] == expected
    assert job["anomaly_count"] == len(events) >= 1
    assert job["source"] == "pcap_upload"
    assert job["stats"]["packets"] == 10


def test_events_are_scoped_to_their_job(client, test_pcap, weak_pcap):
    a = _upload(client, test_pcap).json()["job_id"]
    b = _upload(client, weak_pcap).json()["job_id"]
    a_events = client.get("/events", params={"job_id": a}).json()
    b_events = client.get("/events", params={"job_id": b}).json()
    assert a_events and b_events
    # the same aggressive-mode SA in both captures: same deterministic id, two jobs
    assert len(client.get("/events").json()) == len(a_events) + len(b_events)


def test_evidence_frames_index_into_the_downloadable_capture(client, ingested, test_pcap):
    """The whole point of evidence: the frames must exist in the file we hand back."""
    event = client.get("/events", params={"job_id": ingested}).json()[0]
    assert event["evidence_pkts"]
    capture = client.get(f"/jobs/{ingested}/capture")
    assert capture.status_code == 200
    assert capture.content == test_pcap.read_bytes()

    from scapy.utils import rdpcap

    frames = len(rdpcap(io.BytesIO(capture.content)))
    assert all(1 <= n <= frames for n in event["evidence_pkts"])


def test_unknown_job_is_404(client):
    assert client.get("/jobs/nope").status_code == 404
    assert client.get("/jobs/nope/capture").status_code == 404
    assert client.delete("/jobs/nope").status_code == 404


def test_deleting_a_job_removes_everything_it_found(client, ingested, tmp_path):
    assert client.delete(f"/jobs/{ingested}").status_code == 204
    assert client.get(f"/jobs/{ingested}").status_code == 404
    assert client.get("/sessions", params={"job_id": ingested}).json() == []
    assert client.get("/events", params={"job_id": ingested}).json() == []
    assert list((tmp_path / "captures").glob("*")) == []


def test_non_capture_upload_is_rejected(client):
    resp = client.post("/ingest", files={"file": ("notes.pcap", b"hello, this is not a pcap")})
    assert resp.status_code == 415
    assert client.get("/jobs").json() == []


def test_oversize_upload_is_rejected(client, test_pcap, monkeypatch, tmp_path):
    monkeypatch.setenv("VAULTSCOPE_MAX_UPLOAD_MB", "0.0001")  # ~100 bytes
    assert _upload(client, test_pcap).status_code == 413
    assert list((tmp_path / "captures").glob("*")) == []


def test_truncated_capture_is_a_clean_error_not_a_500(client):
    resp = client.post("/ingest", files={"file": ("bad.pcap", b"\xd4\xc3\xb2\xa1garbage")})
    assert resp.status_code in (200, 422)
    if resp.status_code == 200:
        assert resp.json()["session_count"] == 0


def test_rules_endpoint_serves_the_rule_table(client):
    rules = client.get("/rules").json()
    assert {r["id"] for r in rules} >= {"R01", "R04", "R10", "R16"}
    r04 = next(r for r in rules if r["id"] == "R04")
    assert r04["severity"] == "CRITICAL" and "LOGJAM" in r04["standard"]


def test_legacy_database_is_migrated_on_start(tmp_path, monkeypatch):
    """A DB from the previous release (no job columns, events keyed on id) keeps working."""
    import sqlite3

    db = tmp_path / "old.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE jobs (job_id TEXT PRIMARY KEY, capture_file TEXT, "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')));"
        "CREATE TABLE events (anomaly_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, "
        "session_id TEXT NOT NULL, severity TEXT NOT NULL, document TEXT NOT NULL);"
        "INSERT INTO jobs (job_id, capture_file) VALUES ('old', 'old.pcap');"
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("VAULTSCOPE_DB", str(db))

    from api import store

    store.init_db()
    [job] = store.list_jobs()
    assert job.job_id == "old" and job.source == "pcap_upload" and job.session_count == 0


# --- exposure: CORS and the operator token ----------------------------------------


def test_only_configured_origins_may_call_from_a_browser(client):
    allowed = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    stranger = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in stranger.headers


def test_deleting_evidence_needs_the_operator_token_when_one_is_set(client, ingested, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_API_TOKEN", "s3cret")
    assert client.delete(f"/jobs/{ingested}").status_code == 401
    assert (
        client.delete(f"/jobs/{ingested}", headers={"X-VaultScope-Token": "nope"}).status_code
        == 401
    )
    ok = client.delete(f"/jobs/{ingested}", headers={"X-VaultScope-Token": "s3cret"})
    assert ok.status_code == 204


def test_uploads_stay_open_when_a_token_is_set(client, test_pcap, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_API_TOKEN", "s3cret")
    assert _upload(client, test_pcap).status_code == 200


def test_interface_capture_needs_the_token_and_can_be_disabled(client, monkeypatch):
    body = {"source": "interface", "interface": "no-such-nic0"}
    monkeypatch.setenv("VAULTSCOPE_API_TOKEN", "s3cret")
    assert client.post("/live/start", json=body).status_code == 401
    monkeypatch.setenv("VAULTSCOPE_INTERFACE_CAPTURE", "0")
    assert client.post("/live/start", json=body).status_code == 403
    assert client.get("/health").json()["live"]["interface_capture"] is False
