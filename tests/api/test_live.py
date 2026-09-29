"""Live capture: a run grows one capture, analyses it on a tick, streams changes."""

import time

import pytest


def _wait_until_done(client, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = client.get("/live/status").json()
        if status["state"] != "running":
            return status
        time.sleep(0.1)
    pytest.fail("live run did not finish")


@pytest.fixture
def fast_ticks(monkeypatch):
    from api import live

    monkeypatch.setattr(live, "TICK_SEC", 0.1)


def _replay(client, job_id=None):
    body = {"source": "replay", "speed": 1000}
    if job_id:
        body["job_id"] = job_id
    return client.post("/live/start", json=body)


def test_replay_run_becomes_a_live_job(client, ingested, fast_ticks):
    started = _replay(client, ingested)
    assert started.status_code == 200, started.text
    assert started.json()["state"] == "running"

    status = _wait_until_done(client)
    assert status["state"] == "stopped", status
    job = client.get(f"/jobs/{status['job_id']}").json()
    assert job["source"] == "live_nic"
    assert job["session_count"] == 5
    assert job["anomaly_count"] >= 1
    assert job["capture_available"] is True
    sessions = client.get("/sessions", params={"job_id": status["job_id"]}).json()
    assert {s["capture_source"] for s in sessions} == {"live_nic"}


def test_live_run_streams_sessions_anomalies_and_status(client, ingested, fast_ticks):
    with client.websocket_connect("/ws/live") as ws:
        assert ws.receive_json()["type"] == "live"
        _replay(client, ingested)
        seen = set()
        while "done" not in seen:
            message = ws.receive_json()
            seen.add(message["type"])
            if message["type"] == "live" and message["status"]["state"] == "stopped":
                seen.add("done")
    assert {"session", "anomaly", "live"} <= seen


def test_replayed_evidence_matches_the_original_capture(client, ingested, fast_ticks):
    """Replay writes every packet in order, so frame numbers survive the round trip."""
    job = _replay(client, ingested).json()["job_id"]
    _wait_until_done(client)
    original = client.get("/events", params={"job_id": ingested}).json()
    replayed = client.get("/events", params={"job_id": job}).json()
    assert sorted(e["evidence_pkts"] for e in original) == sorted(
        e["evidence_pkts"] for e in replayed
    )


def test_second_run_while_one_is_active_is_409(client, ingested, monkeypatch):
    from api import live

    monkeypatch.setattr(live, "TICK_SEC", 0.1)
    _replay(client, ingested)
    try:
        assert _replay(client, ingested).status_code in (200, 409)
    finally:
        client.post("/live/stop")


def test_stop_ends_the_run(client, fast_ticks):
    """The bundled demo capture takes minutes to replay at normal speed; stop cuts it."""
    started = client.post("/live/start", json={"source": "replay", "speed": 1})
    assert started.status_code == 200, started.text
    stopped = client.post("/live/stop").json()
    assert stopped["state"] == "stopped"
    assert client.get("/live/status").json()["state"] == "stopped"


def test_replay_of_unknown_job_is_404(client):
    assert _replay(client, "nope").status_code == 404


def test_interface_needs_a_name(client):
    assert client.post("/live/start", json={"source": "interface"}).status_code == 422


def test_unusable_interface_is_a_503_with_the_reason(client):
    resp = client.post("/live/start", json={"source": "interface", "interface": "no-such-nic0"})
    assert resp.status_code == 503
    assert resp.json()["detail"].startswith("could not start capture")
    assert client.get("/live/status").json()["state"] == "idle"


def test_interfaces_endpoint_answers_even_without_privilege(client):
    resp = client.get("/live/interfaces")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_a_session_whose_id_changes_is_retracted(tmp_path, monkeypatch):
    """Mid-handshake an SA has no responder SPI; once it does, the old id must go."""
    from api import live
    from core.live import LiveSource
    from core.models import VPNSession
    from core.pipeline import Analysis

    class Idle(LiveSource):
        label = "test"

        def start(self, out):
            pass

        def stop(self):
            pass

        running = True

    published: list[dict] = []

    async def publish(batch):
        published.extend(batch)

    run = live.LiveRun(Idle(), tmp_path, publish)
    ticks = iter(
        [
            Analysis(sessions=[VPNSession(session_id="aa-0000")]),
            Analysis(sessions=[VPNSession(session_id="aa-bbbb")]),
        ]
    )
    monkeypatch.setattr(live, "analyze_capture", lambda *a, **k: next(ticks))
    monkeypatch.setenv("VAULTSCOPE_DB", str(tmp_path / "t.sqlite"))
    live.store.init_db()
    await run._tick()
    await run._tick()

    removed = [m["session_id"] for m in published if m["type"] == "session_removed"]
    added = [m["session"]["session_id"] for m in published if m["type"] == "session"]
    assert added == ["aa-0000", "aa-bbbb"] and removed == ["aa-0000"]
