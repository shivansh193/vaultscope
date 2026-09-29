"""Drives one live-capture run: a source grows a file, this analyses it on a tick.

Each tick re-analyses the whole capture so far -- the Analysis module is
stateless and fast (a few thousand packets a second), and re-reading the file
is what keeps sessions whole when an SA's handshake and its ESP land in
different ticks. The run is one job: every tick replaces that job's sessions
and events, then pushes only what changed to the WebSocket subscribers.

A run ends when the operator stops it, when a replay reaches the end of its
capture, or at ``MAX_PACKETS`` so re-analysis cost stays bounded.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from api import store
from core.live import LiveSource, wait_for_file
from core.models import AnomalyEvent, CaptureStats, VPNSession
from core.pipeline import analyze_capture

log = logging.getLogger(__name__)

TICK_SEC = 2.0
MAX_PACKETS = 250_000

Publish = Callable[[list[dict]], Awaitable[None]]


def messages(job_id: str, sessions: list[VPNSession], anomalies: list[AnomalyEvent]) -> list[dict]:
    """WebSocket envelopes for ``/ws/live``: one per session, one per anomaly."""
    return [
        {"type": "session", "job_id": job_id, "session": s.model_dump(mode="json")}
        for s in sessions
    ] + [
        {"type": "anomaly", "job_id": job_id, "anomaly": e.model_dump(mode="json")}
        for e in anomalies
    ]


class LiveStatus(BaseModel):
    state: Literal["idle", "running", "stopped", "error"] = "idle"
    job_id: str | None = None
    source: str | None = None
    started_at: str | None = None
    stats: CaptureStats = CaptureStats()
    error: str | None = None


class LiveRun:
    def __init__(self, source: LiveSource, capture_dir: Path, publish: Publish) -> None:
        self.source = source
        self.job_id = f"live-{uuid.uuid4().hex[:12]}"
        self.path = capture_dir / f"{self.job_id}.pcap"
        self.publish = publish
        self.status = LiveStatus(
            state="running",
            job_id=self.job_id,
            source=source.label,
            started_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        )
        self._seen_sessions: dict[str, tuple] = {}
        self._seen_events: set[str] = set()
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def start_loop(self) -> None:
        """Begin ticking. The caller has already started ``source`` on ``path``."""
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            await self._task

    async def _loop(self) -> None:
        size = -1
        try:
            await asyncio.to_thread(wait_for_file, self.path)
            while True:
                finished = self._stopping.is_set() or not self.source.running
                if finished:
                    await asyncio.to_thread(self.source.stop)
                current = self.path.stat().st_size if self.path.exists() else 0
                if current >= 24 and current != size:
                    size = current
                    await self._tick()
                if finished or self.status.stats.packets >= MAX_PACKETS:
                    break
                try:
                    await asyncio.wait_for(self._stopping.wait(), TICK_SEC)
                except TimeoutError:
                    pass
            await asyncio.to_thread(self.source.stop)
            self.status.error = self.source.error
            self.status.state = "error" if self.source.error else "stopped"
        except Exception as exc:
            log.exception("live run %s failed", self.job_id)
            await asyncio.to_thread(self.source.stop)
            self.status.state, self.status.error = "error", str(exc)
        await self.publish([self.status_message()])

    def status_message(self) -> dict:
        return {"type": "live", "status": self.status.model_dump(mode="json")}

    async def _tick(self) -> None:
        analysis = await asyncio.to_thread(analyze_capture, self.path, "live_nic")
        store.save_analysis(
            self.job_id,
            analysis.sessions,
            analysis.anomalies,
            analysis.stats,
            capture_file=self.path.name,
            source="live_nic",
            capture_path=str(self.path),
        )
        self.status.stats = analysis.stats

        changed = []
        for s in analysis.sessions:
            fingerprint = (
                s.security_assessment.risk_score,
                s.flow_features.pkt_total,
                s.traffic_prediction.predicted_type,
            )
            if self._seen_sessions.get(s.session_id) != fingerprint:
                self._seen_sessions[s.session_id] = fingerprint
                changed.append(s)
        # An SA caught mid-handshake has no responder SPI yet, so its id changes
        # once the response lands. Retract ids the newest analysis no longer has.
        current = {s.session_id for s in analysis.sessions}
        gone = [sid for sid in self._seen_sessions if sid not in current]
        for sid in gone:
            del self._seen_sessions[sid]
        retractions = [
            {"type": "session_removed", "job_id": self.job_id, "session_id": sid} for sid in gone
        ]

        fresh = [e for e in analysis.anomalies if e.anomaly_id not in self._seen_events]
        self._seen_events.update(e.anomaly_id for e in fresh)
        await self.publish(
            retractions + messages(self.job_id, changed, fresh) + [self.status_message()]
        )
