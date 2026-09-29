"""Hash-chained audit log: every stored analysis is committed, edits are caught."""

from api import store
from core.models import CaptureStats, VPNSession


def _save(job_id: str, score: int = 100) -> None:
    session = VPNSession(session_id=f"s-{job_id}")
    session.security_assessment.risk_score = score
    store.save_analysis(job_id, [session], [], CaptureStats(sessions=1))


def test_chain_links_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_DB", str(tmp_path / "a.sqlite"))
    store.reset()
    _save("j1")
    _save("j2")
    _save("j2")  # unchanged re-save (a quiet live tick) adds nothing
    entries = store.audit_entries()
    assert [e["job_id"] for e in entries] == ["j1", "j2"]
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert store.verify_audit_chain()["ok"]


def test_edited_result_is_detected(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_DB", str(tmp_path / "a.sqlite"))
    store.reset()
    _save("j1", score=20)
    with store.connect() as conn:
        conn.execute("UPDATE sessions SET document = replace(document, '20', '99')")
    result = store.verify_audit_chain()
    assert not result["ok"]
    assert result["tampered_jobs"] == ["j1"]


def test_rewritten_history_breaks_the_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTSCOPE_DB", str(tmp_path / "a.sqlite"))
    store.reset()
    _save("j1")
    _save("j2")
    with store.connect() as conn:
        conn.execute("UPDATE audit_log SET analysis_sha256 = 'x' WHERE seq = 1")
    assert store.verify_audit_chain()["chain_broken_at_seq"] == 1


def test_audit_endpoints(client):
    assert client.get("/audit/verify").json()["ok"] is True
    assert isinstance(client.get("/audit").json(), list)
