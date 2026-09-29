"""SQLite persistence for jobs, the sessions they found and their anomaly events.

Uses stdlib ``sqlite3`` deliberately: a session is stored as its canonical JSON
document with the few queryable fields lifted into indexed columns. An ORM
would buy nothing over that and adds a dependency the project does not have.

A **job** is one analysed capture -- an upload, or one live-capture run. It
owns its sessions and events, and its summary (severity mix, posture, anomaly
count, capture stats) is answered here so every view of the console reads the
same numbers.

Switching to PostgreSQL at scale (spec Section 6) means replacing this module,
not its callers -- the API only ever calls the functions defined here.
"""

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path

from core.models import (
    SEVERITY_ORDER,
    AnomalyEvent,
    CaptureStats,
    JobSummary,
    VPNSession,
)

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
    anomaly_id  TEXT NOT NULL,
    job_id      TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    document    TEXT NOT NULL,
    PRIMARY KEY (job_id, anomaly_id)
);
CREATE INDEX IF NOT EXISTS idx_events_session  ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_job      ON events(job_id);

CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    capture_file TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# Columns added after the first release. A database created by an older build
# gains them on start-up instead of failing every query that names them.
_JOB_COLUMNS = {
    "source": "TEXT NOT NULL DEFAULT 'pcap_upload'",
    "stats": "TEXT NOT NULL DEFAULT '{}'",
    "capture_path": "TEXT",
}


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
        # Anomaly ids are deterministic per capture, so uploading one capture
        # twice yields the same ids under two jobs. An older build keyed events
        # on anomaly_id alone; rebuild that table keyed on (job_id, anomaly_id).
        pk = [r["name"] for r in conn.execute("PRAGMA table_info(events)") if r["pk"]]
        if pk == ["anomaly_id"]:
            conn.execute("ALTER TABLE events RENAME TO events_v1")
            conn.executescript(_SCHEMA)
            conn.execute("INSERT OR IGNORE INTO events SELECT * FROM events_v1")
            conn.execute("DROP TABLE events_v1")
        conn.executescript(_SCHEMA)
        have = {row["name"] for row in conn.execute("PRAGMA table_info(jobs)")}
        for column, decl in _JOB_COLUMNS.items():
            if column not in have:
                conn.execute(f"ALTER TABLE jobs ADD COLUMN {column} {decl}")


def save_analysis(
    job_id: str,
    sessions: list[VPNSession],
    events: Iterable[AnomalyEvent],
    stats: CaptureStats,
    *,
    capture_file: str | None = None,
    source: str = "pcap_upload",
    capture_path: str | None = None,
) -> None:
    """Record a job's complete analysis, replacing whatever it held before.

    Replacement, not merge: live capture re-analyses its growing file on every
    tick, and the newest analysis of the whole file is the truth.
    """
    with connect() as conn:
        conn.execute(
            "INSERT INTO jobs (job_id, capture_file, source, stats, capture_path) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(job_id) DO UPDATE SET "
            "capture_file = excluded.capture_file, source = excluded.source, "
            "stats = excluded.stats, capture_path = excluded.capture_path",
            (job_id, capture_file, source, stats.model_dump_json(), capture_path),
        )
        conn.execute("DELETE FROM sessions WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM events WHERE job_id = ?", (job_id,))
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


def get_session(session_id: str, job_id: str | None = None) -> VPNSession | None:
    """The newest record of ``session_id`` -- the same SA can appear in several jobs."""
    query = "SELECT document FROM sessions WHERE session_id = ?"
    params: list[str] = [session_id]
    if job_id:
        query += " AND job_id = ?"
        params.append(job_id)
    with connect() as conn:
        row = conn.execute(f"{query} ORDER BY created_at DESC LIMIT 1", params).fetchone()
    return VPNSession(**json.loads(row["document"])) if row else None


def list_events(
    session_id: str | None = None,
    severity: str | None = None,
    job_id: str | None = None,
) -> list[AnomalyEvent]:
    clauses, params = [], []
    for column, value in (("session_id", session_id), ("severity", severity), ("job_id", job_id)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with connect() as conn:
        rows = conn.execute(f"SELECT document FROM events {where}", params).fetchall()
    events = [AnomalyEvent(**json.loads(r["document"])) for r in rows]
    return sorted(events, key=lambda e: (SEVERITY_ORDER.index(e.severity), e.timestamp))


def _summary(conn: sqlite3.Connection, row: sqlite3.Row) -> JobSummary:
    job_id = row["job_id"]
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    total, score_sum = 0, 0
    for sev, n, scores in conn.execute(
        "SELECT severity, COUNT(*), SUM(risk_score) FROM sessions WHERE job_id = ? "
        "GROUP BY severity",
        (job_id,),
    ):
        counts[sev] = n
        total += n
        score_sum += scores or 0
    anomalies = conn.execute("SELECT COUNT(*) FROM events WHERE job_id = ?", (job_id,)).fetchone()
    path = row["capture_path"]
    return JobSummary(
        job_id=job_id,
        capture_file=row["capture_file"],
        source=row["source"],
        created_at=row["created_at"],
        stats=CaptureStats(**json.loads(row["stats"] or "{}")),
        session_count=total,
        severity_counts=counts,
        posture_score=round(score_sum / total) if total else 100,
        anomaly_count=anomalies[0],
        capture_available=bool(path) and Path(path).is_file(),
    )


def list_jobs(limit: int = 100) -> list[JobSummary]:
    """Newest first."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_summary(conn, row) for row in rows]


def get_job(job_id: str) -> JobSummary | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return _summary(conn, row) if row else None


def capture_path(job_id: str) -> Path | None:
    """The stored capture behind a job, if it is still on disk."""
    with connect() as conn:
        row = conn.execute("SELECT capture_path FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None or not row["capture_path"]:
        return None
    path = Path(row["capture_path"])
    return path if path.is_file() else None


def delete_job(job_id: str) -> bool:
    """Forget a job and everything it found. True when there was one to delete."""
    path = capture_path(job_id)
    with connect() as conn:
        deleted = conn.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,)).rowcount
        conn.execute("DELETE FROM sessions WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM events WHERE job_id = ?", (job_id,))
    if path is not None:
        path.unlink(missing_ok=True)
    return bool(deleted)


def job_exists(job_id: str) -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone() is not None


def reset() -> None:
    """Drop all rows. Test-support only."""
    init_db()
    with connect() as conn:
        for table in ("sessions", "events", "jobs"):
            conn.execute(f"DELETE FROM {table}")
