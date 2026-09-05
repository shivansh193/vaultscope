"""VaultScope FastAPI backend (P3-T7, P3-T8, P3-T9, P3-T10).

Routes follow the API contract in spec Section 11. Swagger UI is auto-generated
at ``/docs``.
"""

import asyncio
import contextlib
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api import store
from core import pipeline
from core.anomalies import detect_anomalies
from core.models import AnomalyEvent, VPNSession
from reporting import export, render

VERSION = "1.0.0"

REPORT_DIR = Path(__file__).resolve().parent.parent / "reporting" / "out"
UPLOAD_DIR = Path(tempfile.gettempdir()) / "vaultscope-uploads"

app = FastAPI(
    title="VaultScope",
    version=VERSION,
    description="AI-powered IPsec VPN protocol analyzer and security assessment framework.",
)

# The dashboard is served from a different origin in dev (Vite on :5173) and
# from nginx in Compose. Wide-open CORS is acceptable for an on-premise
# analysis tool with no authentication surface; tighten if that changes.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    store.init_db()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class IngestResponse(BaseModel):
    session_count: int
    job_id: str
    fixture_mode: bool


class HealthResponse(BaseModel):
    status: str
    version: str
    parser_available: bool


class ReportRequest(BaseModel):
    type: Literal["executive", "technical", "json", "cef"]


class ReportResponse(BaseModel):
    download_url: str


class DiffResponse(BaseModel):
    added: list[str]
    removed: list[str]
    degraded: list[dict]


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """`parser_available` is false while Block A's Stage 2 parser is unbuilt,
    in which case /ingest returns fixture sessions -- see core.pipeline."""
    return HealthResponse(
        status="ok", version=VERSION, parser_available=pipeline.parser_available()
    )


@app.post("/ingest", response_model=IngestResponse)
async def ingest(file: UploadFile = File(...)) -> IngestResponse:
    """Analyse an uploaded pcap and persist the resulting sessions."""
    job_id = str(uuid.uuid4())
    target = UPLOAD_DIR / f"{job_id}-{Path(file.filename or 'capture.pcap').name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)

        # Analysis is CPU-bound and synchronous; keep the event loop free so
        # /ws/live subscribers are not blocked by a large upload.
        sessions = await asyncio.to_thread(pipeline.analyze_capture, target, "pcap_upload")
    finally:
        await file.close()
        target.unlink(missing_ok=True)

    store.save_sessions(job_id, sessions, capture_file=file.filename)
    store.save_events(job_id, detect_anomalies(sessions))
    await _broadcast(sessions)

    return IngestResponse(
        session_count=len(sessions),
        job_id=job_id,
        fixture_mode=not pipeline.parser_available(),
    )


@app.get("/sessions", response_model=list[VPNSession])
def get_sessions(
    severity: str | None = None,
    job_id: str | None = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[VPNSession]:
    return store.list_sessions(severity=severity, job_id=job_id, limit=limit, offset=offset)


@app.get("/session/{session_id}", response_model=VPNSession)
def get_session(session_id: str) -> VPNSession:
    session = store.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"no session {session_id}")
    return session


@app.get("/events", response_model=list[AnomalyEvent])
def get_events(session_id: str | None = None, severity: str | None = None) -> list[AnomalyEvent]:
    return store.list_events(session_id=session_id, severity=severity)


@app.get("/sessions/diff", response_model=DiffResponse)
def diff(base_job: str, compare_job: str) -> DiffResponse:
    """Compare two captures: new peers, gone peers, and sessions that got worse."""
    for job in (base_job, compare_job):
        if not store.job_exists(job):
            raise HTTPException(status_code=404, detail=f"no job {job}")

    base = {s.session_id: s for s in store.list_sessions(job_id=base_job, limit=1000)}
    compare = {s.session_id: s for s in store.list_sessions(job_id=compare_job, limit=1000)}

    degraded = [
        {
            "session_id": sid,
            "base_score": base[sid].security_assessment.risk_score,
            "compare_score": compare[sid].security_assessment.risk_score,
            "base_severity": base[sid].security_assessment.overall_severity,
            "compare_severity": compare[sid].security_assessment.overall_severity,
        }
        for sid in base.keys() & compare.keys()
        if compare[sid].security_assessment.risk_score < base[sid].security_assessment.risk_score
    ]
    return DiffResponse(
        added=sorted(compare.keys() - base.keys()),
        removed=sorted(base.keys() - compare.keys()),
        degraded=degraded,
    )


_REPORT_BUILDERS = {
    "executive": ("pdf", lambda s, p, n: render.write_executive_pdf(s, p, n)),
    "technical": ("html", lambda s, p, n: render.write_technical_html(s, p, n)),
    "json": ("json", lambda s, p, n: export.write_json(s, p)),
    "cef": ("cef", lambda s, p, n: export.write_cef(s, p)),
}


@app.post("/report/{job_id}", response_model=ReportResponse)
async def build_report(job_id: str, request: ReportRequest) -> ReportResponse:
    sessions = store.list_sessions(job_id=job_id, limit=1000)
    if not sessions:
        raise HTTPException(status_code=404, detail=f"no sessions for job {job_id}")

    suffix, builder = _REPORT_BUILDERS[request.type]
    path = REPORT_DIR / f"{job_id}-{request.type}.{suffix}"
    capture_name = sessions[0].capture_file
    await asyncio.to_thread(builder, sessions, path, capture_name)

    return ReportResponse(download_url=f"/report/download/{path.name}")


@app.get("/report/download/{filename}")
def download_report(filename: str) -> FileResponse:
    # Resolve and confine to REPORT_DIR: `filename` is user-controlled and
    # could otherwise traverse out with '..' or an absolute path.
    path = (REPORT_DIR / filename).resolve()
    if not path.is_relative_to(REPORT_DIR.resolve()) or not path.is_file():
        raise HTTPException(status_code=404, detail="no such report")
    return FileResponse(path, filename=path.name)


# --- live capture stream (P3-T8) -------------------------------------------

_subscribers: set[WebSocket] = set()


async def _broadcast(sessions: list[VPNSession]) -> None:
    """Push new sessions to every live subscriber; drop those that have gone."""
    if not _subscribers:
        return
    dead = set()
    for socket in list(_subscribers):
        try:
            for session in sessions:
                await socket.send_json(session.model_dump(mode="json"))
        except (WebSocketDisconnect, RuntimeError):
            dead.add(socket)
    _subscribers.difference_update(dead)


@app.websocket("/ws/live")
async def live(websocket: WebSocket, nic: str | None = None) -> None:
    """Stream sessions as they are detected.

    Every ingest broadcasts here, so the dashboard updates without polling.
    Live NIC capture itself is Stage 1 (Block A); until that lands this carries
    upload-driven sessions only.
    """
    await websocket.accept()
    _subscribers.add(websocket)
    try:
        while True:
            # Keep the connection open; the client is not required to send.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        with contextlib.suppress(KeyError):
            _subscribers.remove(websocket)
