"""SQLite persistence for analysed sessions and anomaly events.

Uses stdlib ``sqlite3`` deliberately: a session is stored as its canonical JSON
document with the few queryable fields lifted into indexed columns. An ORM
would buy nothing over that and adds a dependency the project does not have.

Switching to PostgreSQL at scale (spec Section 6) means replacing this module,
not its callers -- the API only ever calls the functions defined here.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from core.models import AnomalyEvent, VPNSession

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "vaultscope.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    job_id      TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    document    TEXT NOT NULL,
    PRIMARY KEY (job_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_severity ON sessions(severity);
CREATE INDEX IF NOT EXISTS idx_sessions_job      ON sessions(job_id);

CREATE TABLE IF NOT EXISTS events (
    anomaly_id  TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    document    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session  ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    capture_file TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def db_path() -> Path:
    """Honours VAULTSCOPE_DB so tests and Compose can point at their own file."""
    return Path(os.environ.get("VAULTSCOPE_DB", DEFAULT_DB_PATH))


@contextmanager
def connect():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(_SCHEMA)


def save_sessions(job_id: str, sessions: list[VPNSession], capture_file: str | None = None) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO jobs (job_id, capture_file) VALUES (?, ?)",
            (job_id, capture_file),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO sessions "
            "(job_id, session_id, severity, risk_score, document) VALUES (?, ?, ?, ?, ?)",
            [
                (
                    job_id,
                    s.session_id,
                    s.security_assessment.overall_severity,
                    s.security_assessment.risk_score,
                    s.model_dump_json(),
                )
                for s in sessions
            ],
        )


def save_events(job_id: str, events: list[AnomalyEvent]) -> None:
    with connect() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO events "
            "(anomaly_id, job_id, session_id, severity, document) VALUES (?, ?, ?, ?, ?)",
            [(e.anomaly_id, job_id, e.session_id, e.severity, e.model_dump_json()) for e in events],
        )


def list_sessions(
    severity: str | None = None,
    job_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[VPNSession]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if job_id:
        clauses.append("job_id = ?")
        params.append(job_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with connect() as conn:
        rows = conn.execute(
            f"SELECT document FROM sessions {where} "
            "ORDER BY risk_score ASC, session_id ASC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return [VPNSession(**json.loads(r["document"])) for r in rows]


def get_session(session_id: str) -> VPNSession | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT document FROM sessions WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        ).fetchone()
    return VPNSession(**json.loads(row["document"])) if row else None


def list_events(session_id: str | None = None, severity: str | None = None) -> list[AnomalyEvent]:
    clauses, params = [], []
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with connect() as conn:
        rows = conn.execute(f"SELECT document FROM events {where}", params).fetchall()
    return [AnomalyEvent(**json.loads(r["document"])) for r in rows]


def job_exists(job_id: str) -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone() is not None


def reset() -> None:
    """Drop all rows. Test-support only."""
    with connect() as conn:
        conn.executescript(_SCHEMA)
        for table in ("sessions", "events", "jobs"):
            conn.execute(f"DELETE FROM {table}")
