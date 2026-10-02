"""Hosted-demo seeding: an empty store gets the bundled demo capture once."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient


def _wait_for_jobs(client: TestClient, timeout: float = 90.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        jobs = client.get("/jobs").json()
        if jobs:
            return jobs
        time.sleep(0.5)
    return []


def test_empty_store_is_seeded_with_the_demo_capture(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_DB", str(tmp_path / "seed.sqlite"))
    monkeypatch.setenv("VAULTSCOPE_SEED_DEMO", "1")

    from api import main, store

    monkeypatch.setattr(main, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(main, "CAPTURE_DIR", tmp_path / "captures")
    monkeypatch.setattr(main, "_run", None)
    store.init_db()
    with TestClient(main.app) as client:
        jobs = _wait_for_jobs(client)
        assert len(jobs) == 1
        assert jobs[0]["capture_file"] == "demo_capture.pcap"
        assert client.get("/sessions", params={"job_id": jobs[0]["job_id"]}).json()


def test_seed_is_off_by_default(client):
    assert client.get("/jobs").json() == []
