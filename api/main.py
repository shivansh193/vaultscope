"""VaultScope FastAPI backend (P3-T7, P3-T8, P3-T9, P3-T10).

Routes follow the API contract in spec Section 11, extended with jobs (one
analysed capture each), the rule table, and live capture. Swagger UI is
auto-generated at ``/docs``.

Configuration is environment-only so the same image runs in dev, Compose and CI:

    VAULTSCOPE_DB             SQLite file                 (repo/vaultscope.sqlite)
    VAULTSCOPE_REPORT_DIR     rendered reports            (repo/reporting/out)
    VAULTSCOPE_CAPTURE_DIR    stored captures             (repo/data/captures)
    VAULTSCOPE_KEEP_CAPTURES  keep uploads for evidence   (1)
    VAULTSCOPE_MAX_UPLOAD_MB  upload size cap             (512)
    VAULTSCOPE_CORS_ORIGINS   browser origins allowed     (http://localhost:3000,http://127.0.0.1:3000)
    VAULTSCOPE_API_TOKEN      operator token for deleting jobs and interface capture (unset: open)
    VAULTSCOPE_INTERFACE_CAPTURE  0 disables live capture on real NICs          (1)
"""

import asyncio
import contextlib
import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from api import live, store
from core import live as sources
from core.classifiers import model_info
from core.models import (
    AnomalyEvent,
    CaptureStats,
    JobSummary,
    Severity,
    VPNSession,
)
from core.pipeline import analyze_capture
from core.rules.engine import load_rules
from reporting import export, render

VERSION = "1.1.0"

ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = Path(os.environ.get("VAULTSCOPE_REPORT_DIR", ROOT / "reporting" / "out"))
CAPTURE_DIR = Path(os.environ.get("VAULTSCOPE_CAPTURE_DIR", ROOT / "data" / "captures"))
DEMO_CAPTURE = ROOT / "data" / "demo" / "demo_capture.pcap"
_METRICS_PATH = ROOT / "models" / "eval_metrics.json"


def _keep_captures() -> bool:
    return os.environ.get("VAULTSCOPE_KEEP_CAPTURES", "1") not in ("0", "false", "no")


def _max_upload_bytes() -> int:
    return int(float(os.environ.get("VAULTSCOPE_MAX_UPLOAD_MB", "512")) * 1024 * 1024)


# First four bytes of every format read_capture accepts: pcap in both byte
# orders, microsecond and nanosecond, and pcapng's Section Header Block.
_CAPTURE_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ".pcap",
    b"\xa1\xb2\xc3\xd4": ".pcap",
    b"\x4d\x3c\xb2\xa1": ".pcap",
    b"\xa1\xb2\x3c\x4d": ".pcap",
    b"\x0a\x0d\x0d\x0a": ".pcapng",
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init_db()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    yield
    if _run is not None and _run.status.state == "running":
        await _run.stop()


app = FastAPI(
    title="VaultScope",
    version=VERSION,
    description=(
        "AI-powered IPsec VPN protocol analyzer and security assessment framework "
        "(SIH 2026 · SIH26160). Upload a capture or start a live run; every IKE SA "
        "comes back parsed, classified and scored, with cross-session attack "
        "indicators pointing at pcap frame numbers."
    ),
    lifespan=lifespan,
)

# The console is served same-origin by nginx in Compose, so production needs no
# CORS at all. Only the listed origins (the dev server by default, or a hosted
# console) may call the API from a browser: an open policy would let any page
# the operator visits delete jobs or start a capture on a local backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        o.strip()
        for o in os.environ.get(
            "VAULTSCOPE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
        ).split(",")
        if o.strip()
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_operator(x_vaultscope_token: str | None = Header(None)) -> None:
    """Guard for destructive and privileged routes when VAULTSCOPE_API_TOKEN is set.

    Analysis stays open -- a judge uploading a capture needs no credentials --
    but deleting evidence or sniffing a real interface needs the operator.
    """
    expected = os.environ.get("VAULTSCOPE_API_TOKEN")
    if expected and not hmac.compare_digest(x_vaultscope_token or "", expected):
        raise HTTPException(401, "operator token required (X-VaultScope-Token)")


def _interface_capture_enabled() -> bool:
    return os.environ.get("VAULTSCOPE_INTERFACE_CAPTURE", "1") not in ("0", "false", "no")


# --- response models -----------------------------------------------------------


class ModelHealth(BaseModel):
    trained: bool
    model_version: str
    algo: str | None = None


class LiveHealth(BaseModel):
    interface_capture: bool = Field(description="dumpcap is installed on the backend host")
    replay: bool = Field(description="the bundled demo capture is present for replay")
    state: str


class HealthResponse(BaseModel):
    status: str
    version: str
    rule_count: int
    model: ModelHealth
    live: LiveHealth


class IngestResponse(BaseModel):
    job_id: str
    session_count: int
    anomaly_count: int
    stats: CaptureStats


class Rule(BaseModel):
    id: str
    description: str
    severity: Severity
    cve: str | None = None
    standard: str = ""


class ReportRequest(BaseModel):
    type: Literal["executive", "technical", "json", "cef"]


class ReportResponse(BaseModel):
    download_url: str


class DegradedSession(BaseModel):
    """A session both captures hold, whose assessment got worse.

    Carries both whole records, not just the delta: the caller comparing two
    captures is about to ask *what* changed, and making it re-fetch two
    sessions to answer that is a round trip for nothing.
    """

    session_id: str
    base: VPNSession
    compare: VPNSession
    base_score: int
    compare_score: int
    base_severity: Severity
    compare_severity: Severity


class DiffResponse(BaseModel):
    added: list[VPNSession]
    removed: list[VPNSession]
    degraded: list[DegradedSession]


class LiveStartRequest(BaseModel):
    source: Literal["replay", "interface"] = "replay"
    interface: str | None = Field(None, description="NIC name, for source=interface")
    job_id: str | None = Field(
        None, description="replay this stored job's capture instead of the bundled demo"
    )
    speed: float = Field(20.0, gt=0, le=1000, description="replay time compression")


class Interface(BaseModel):
    name: str
    description: str = ""


# --- system -----------------------------------------------------------------------


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    info = model_info()
    return HealthResponse(
        status="ok",
        version=VERSION,
        rule_count=len(load_rules()),
        model=ModelHealth(
            trained=info["trained"], model_version=info["model_version"], algo=info.get("algo")
        ),
        live=LiveHealth(
            interface_capture=_interface_capture_enabled() and sources.dumpcap_path() is not None,
            replay=DEMO_CAPTURE.is_file(),
            state=_run.status.state if _run else "idle",
        ),
    )


@app.get("/model/metrics", tags=["system"])
def model_metrics() -> dict:
    """Stage 4b evaluation artifacts for the dashboard: accuracy, macro-F1,
    per-class scores and RandomForest feature importances. ``{}`` until a model
    is trained (`python -m core.classifiers.train`)."""
    try:
        return json.loads(_METRICS_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


@app.get("/rules", response_model=list[Rule], tags=["system"])
def rules() -> list[Rule]:
    """The Stage 4c rule table every session is scored against."""
    return [
        Rule(
            id=r["id"],
            description=r["description"],
            severity=r["severity"],
            cve=r.get("cve"),
            standard=r.get("standard") or "",
        )
        for r in load_rules()
    ]


# --- ingest + jobs ------------------------------------------------------------------


async def _receive(file: UploadFile, job_id: str) -> Path:
    """Stream the upload to disk, rejecting non-captures and oversize files early."""
    head = await file.read(4)
    suffix = _CAPTURE_MAGIC.get(head)
    if suffix is None:
        raise HTTPException(415, "not a pcap or pcapng capture (unrecognised file header)")
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    target = CAPTURE_DIR / f"{job_id}{suffix}"
    limit, written = _max_upload_bytes(), len(head)
    try:
        with target.open("wb") as fh:
            fh.write(head)
            while chunk := await file.read(1 << 20):
                written += len(chunk)
                if written > limit:
                    raise HTTPException(413, f"capture exceeds {limit // (1024 * 1024)} MB")
                fh.write(chunk)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target


@app.post("/ingest", response_model=IngestResponse, tags=["analysis"])
async def ingest(file: UploadFile = File(...)) -> IngestResponse:
    """Analyse an uploaded pcap / pcapng and persist it as a new job."""
    job_id = str(uuid.uuid4())
    try:
        target = await _receive(file, job_id)
    finally:
        await file.close()

    try:
        # CPU-bound: keep the event loop free for /ws/live subscribers.
        analysis = await asyncio.to_thread(analyze_capture, target, "pcap_upload")
    except Exception as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(422, f"capture could not be read: {exc}") from exc

    keep = _keep_captures()
    name = Path(file.filename or target.name).name
    for session in analysis.sessions:
        session.capture_file = name
    await asyncio.to_thread(
        store.save_analysis,
        job_id,
        analysis.sessions,
        analysis.anomalies,
        analysis.stats,
        capture_file=name,
        capture_path=str(target) if keep else None,
    )
    if not keep:
        target.unlink(missing_ok=True)
    await _publish(live.messages(job_id, analysis.sessions, analysis.anomalies))

    return IngestResponse(
        job_id=job_id,
        session_count=len(analysis.sessions),
        anomaly_count=len(analysis.anomalies),
        stats=analysis.stats,
    )


@app.get("/jobs", response_model=list[JobSummary], tags=["jobs"])
def list_jobs(limit: int = Query(100, ge=1, le=1000)) -> list[JobSummary]:
    """Every analysed capture, newest first."""
    return store.list_jobs(limit)


def _job_or_404(job_id: str) -> JobSummary:
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(404, f"no job {job_id}")
    return job


@app.get("/jobs/{job_id}", response_model=JobSummary, tags=["jobs"])
def get_job(job_id: str) -> JobSummary:
    return _job_or_404(job_id)


@app.delete(
    "/jobs/{job_id}", status_code=204, tags=["jobs"], dependencies=[Depends(require_operator)]
)
def delete_job(job_id: str) -> None:
    if _run is not None and _run.job_id == job_id and _run.status.state == "running":
        raise HTTPException(409, "stop the live run before deleting its job")
    if not store.delete_job(job_id):
        raise HTTPException(404, f"no job {job_id}")


@app.get("/jobs/{job_id}/capture", tags=["jobs"])
def download_capture(job_id: str) -> FileResponse:
    """The capture a job analysed -- evidence frame numbers index into this file."""
    job = _job_or_404(job_id)
    path = store.capture_path(job_id)
    if path is None:
        raise HTTPException(404, "capture not retained for this job")
    stem = Path(job.capture_file or path.name).stem
    return FileResponse(path, filename=f"{stem}{path.suffix}")


# --- sessions + events --------------------------------------------------------------


@app.get("/sessions", response_model=list[VPNSession], tags=["analysis"])
def get_sessions(
    severity: Severity | None = None,
    job_id: str | None = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[VPNSession]:
    return store.list_sessions(severity=severity, job_id=job_id, limit=limit, offset=offset)


@app.get("/session/{session_id}", response_model=VPNSession, tags=["analysis"])
def get_session(session_id: str, job_id: str | None = None) -> VPNSession:
    session = store.get_session(session_id, job_id=job_id)
    if session is None:
        raise HTTPException(404, f"no session {session_id}")
    return session


@app.get("/events", response_model=list[AnomalyEvent], tags=["analysis"])
def get_events(
    job_id: str | None = None,
    session_id: str | None = None,
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"] | None = None,
) -> list[AnomalyEvent]:
    """Runtime anomalies, worst first. Scope with ``job_id`` for one capture."""
    return store.list_events(session_id=session_id, severity=severity, job_id=job_id)


@app.get("/sessions/diff", response_model=DiffResponse, tags=["analysis"])
def diff(base_job: str, compare_job: str) -> DiffResponse:
    """Compare two captures: new peers, gone peers, and sessions that got worse."""
    for job in (base_job, compare_job):
        if not store.job_exists(job):
            raise HTTPException(404, f"no job {job}")

    base = {s.session_id: s for s in store.list_sessions(job_id=base_job, limit=100_000)}
    compare = {s.session_id: s for s in store.list_sessions(job_id=compare_job, limit=100_000)}

    degraded = [
        DegradedSession(
            session_id=sid,
            base=base[sid],
            compare=compare[sid],
            base_score=base[sid].security_assessment.risk_score,
            compare_score=compare[sid].security_assessment.risk_score,
            base_severity=base[sid].security_assessment.overall_severity,
            compare_severity=compare[sid].security_assessment.overall_severity,
        )
        for sid in sorted(base.keys() & compare.keys())
        if compare[sid].security_assessment.risk_score < base[sid].security_assessment.risk_score
    ]
    return DiffResponse(
        added=[compare[sid] for sid in sorted(compare.keys() - base.keys())],
        removed=[base[sid] for sid in sorted(base.keys() - compare.keys())],
        degraded=degraded,
    )


# --- reports ------------------------------------------------------------------------

_REPORT_BUILDERS = {
    "executive": ("pdf", render.write_executive_pdf),
    "technical": ("html", render.write_technical_html),
    "json": ("json", lambda s, p, _name, events: export.write_json(s, p, events)),
    "cef": ("cef", lambda s, p, _name, events: export.write_cef(s, p, events)),
}


@app.post("/report/{job_id}", response_model=ReportResponse, tags=["reports"])
async def build_report(job_id: str, request: ReportRequest) -> ReportResponse:
    job = _job_or_404(job_id)
    sessions = store.list_sessions(job_id=job_id, limit=100_000)
    if not sessions:
        raise HTTPException(404, f"no sessions for job {job_id}")
    events = store.list_events(job_id=job_id)

    suffix, builder = _REPORT_BUILDERS[request.type]
    path = REPORT_DIR / f"{job_id}-{request.type}.{suffix}"
    await asyncio.to_thread(builder, sessions, path, job.capture_file, events)
    return ReportResponse(download_url=f"/report/download/{path.name}")


@app.get("/report/download/{filename}", tags=["reports"])
def download_report(filename: str) -> FileResponse:
    # Resolve and confine to REPORT_DIR: `filename` is user-controlled and
    # could otherwise traverse out with '..' or an absolute path.
    path = (REPORT_DIR / filename).resolve()
    if not path.is_relative_to(REPORT_DIR.resolve()) or not path.is_file():
        raise HTTPException(404, "no such report")
    return FileResponse(path, filename=path.name)


# --- live capture (P3-T8) --------------------------------------------------------------

_subscribers: set[WebSocket] = set()
_run: live.LiveRun | None = None
_start_lock = asyncio.Lock()


async def _publish(messages: list[dict]) -> None:
    """Push messages to every live subscriber; drop those that have gone."""
    if not _subscribers or not messages:
        return
    dead = set()
    for socket in list(_subscribers):
        try:
            for message in messages:
                await socket.send_json(message)
        except (WebSocketDisconnect, RuntimeError):
            dead.add(socket)
    _subscribers.difference_update(dead)


@app.get("/live/status", response_model=live.LiveStatus, tags=["live"])
def live_status() -> live.LiveStatus:
    return _run.status if _run else live.LiveStatus()


@app.get("/live/interfaces", response_model=list[Interface], tags=["live"])
async def live_interfaces() -> list[Interface]:
    """NICs the backend can capture on. Empty when dumpcap is missing or unprivileged."""
    return [Interface(**i) for i in await asyncio.to_thread(sources.list_interfaces)]


@app.post("/live/start", response_model=live.LiveStatus, tags=["live"])
async def live_start(
    request: LiveStartRequest, x_vaultscope_token: str | None = Header(None)
) -> live.LiveStatus:
    """Start a live run: sessions stream over ``/ws/live`` and land in a new job."""
    global _run
    async with _start_lock:  # the check and the assignment below must not interleave
        if _run is not None and _run.status.state == "running":
            raise HTTPException(409, f"a live run is already active ({_run.job_id})")
        run = _build_run(request, x_vaultscope_token)
        try:
            await asyncio.to_thread(run.source.start, run.path)
        except (RuntimeError, OSError) as exc:
            raise HTTPException(503, f"could not start capture: {exc}") from exc
        run.start_loop()
        _run = run
    await _publish([run.status_message()])
    return run.status


def _build_run(request: LiveStartRequest, token: str | None) -> live.LiveRun:
    if request.source == "interface":
        if not _interface_capture_enabled():
            raise HTTPException(403, "interface capture is disabled on this deployment")
        require_operator(token)
        if not request.interface:
            raise HTTPException(422, "source=interface needs an interface name")
        source: sources.LiveSource = sources.InterfaceSource(request.interface)
    else:
        capture = store.capture_path(request.job_id) if request.job_id else DEMO_CAPTURE
        if capture is None or not capture.is_file():
            raise HTTPException(404, "no capture available to replay")
        source = sources.ReplaySource(capture, speed=request.speed)
    return live.LiveRun(source, CAPTURE_DIR, _publish)


@app.post("/live/stop", response_model=live.LiveStatus, tags=["live"])
async def live_stop() -> live.LiveStatus:
    if _run is None:
        return live.LiveStatus()
    await _run.stop()
    return _run.status


@app.websocket("/ws/live")
async def live_socket(websocket: WebSocket) -> None:
    """Stream ``{"type": "session" | "anomaly" | "live", ...}`` messages.

    Every upload and every live-run tick publishes here, so the console updates
    without polling. A new subscriber is sent the current live status first.
    """
    await websocket.accept()
    _subscribers.add(websocket)
    status = _run.status if _run else live.LiveStatus()
    await websocket.send_json({"type": "live", "status": status.model_dump(mode="json")})
    try:
        while True:
            # Keep the connection open; the client is not required to send.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        with contextlib.suppress(KeyError):
            _subscribers.remove(websocket)
