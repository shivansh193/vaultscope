"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { AnomalyList } from "@/components/AnomalyList";
import { OperatorToken } from "@/components/OperatorToken";
import { SessionDrilldown } from "@/components/SessionDrilldown";
import { SessionTable } from "@/components/SessionTable";
import { Toolbar } from "@/components/Toolbar";
import { ApiError, health, liveInterfaces, liveStart, liveStop } from "@/lib/api";
import { jobLabel, useJobs } from "@/lib/jobs";
import type { CaptureInterface, VPNSession } from "@/lib/types";
import { useLive } from "@/lib/useLive";

const SOCKET_LABEL = { connecting: "Connecting", open: "Listening", closed: "Disconnected" } as const;
const SOCKET_COLOR = {
  connecting: "var(--label-tertiary)",
  open: "var(--severity-low)",
  closed: "var(--severity-critical)",
} as const;

const control =
  "rounded-md border border-separator bg-surface-raised px-2.5 py-1.5 text-[length:var(--text-footnote)] text-label";

/** "replay:demo" | "replay:<job_id>" | "nic:<name>" */
type SourceKey = string;

export default function LivePage() {
  const router = useRouter();
  const { sessions, anomalies, status, socket, clear } = useLive();
  const { jobs, reload, select } = useJobs();
  const [selected, setSelected] = useState<VPNSession | null>(null);
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [canReplayDemo, setCanReplayDemo] = useState(true);
  const [source, setSource] = useState<SourceKey>("replay:demo");
  const [speed, setSpeed] = useState(50);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [needsToken, setNeedsToken] = useState(false);

  useEffect(() => {
    health()
      .then((h) => {
        setCanReplayDemo(h.live.replay);
        if (h.live.interface_capture) return liveInterfaces().then(setInterfaces);
      })
      .catch(() => undefined);
  }, []);

  // A finished run is a new job: refresh the list so every view can open it.
  useEffect(() => {
    if (status.state === "stopped" || status.state === "error") void reload();
  }, [status.state, reload]);

  const replayable = useMemo(
    () => jobs.filter((j) => j.capture_available && j.source === "pcap_upload"),
    [jobs],
  );
  const running = status.state === "running";
  const flagged = useMemo(() => new Set(anomalies.map((a) => a.session_id)), [anomalies]);

  async function start() {
    setBusy(true);
    setError(undefined);
    try {
      const [kind, value] = [source.slice(0, source.indexOf(":")), source.slice(source.indexOf(":") + 1)];
      // Clear before starting: the first sessions can arrive before the response.
      clear();
      if (kind === "nic") await liveStart({ source: "interface", interface: value });
      else await liveStart({ source: "replay", speed, ...(value === "demo" ? {} : { job_id: value }) });
      setNeedsToken(false);
    } catch (e) {
      setNeedsToken(e instanceof ApiError && e.status === 401);
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      await liveStop();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="h-page flex flex-col">
      <Toolbar title="Live">
        <span
          data-testid="live-state"
          data-state={socket}
          className="flex items-center gap-2 text-[length:var(--text-footnote)] text-label-secondary"
        >
          <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: SOCKET_COLOR[socket] }} />
          {SOCKET_LABEL[socket]}
        </span>
        <button
          type="button"
          onClick={clear}
          disabled={sessions.length === 0 && anomalies.length === 0}
          className={`${control} disabled:opacity-35`}
        >
          Clear
        </button>
      </Toolbar>

      <div className="flex min-h-0 w-full flex-1 overflow-hidden">
        <div className="w-0 flex-1 overflow-y-auto px-4 py-6 md:px-7">
          <section
            data-testid="live-controls"
            className="max-w-4xl rounded-xl border border-separator bg-surface p-4 md:p-5"
          >
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex min-w-0 max-w-full items-center gap-2 text-[length:var(--text-footnote)] text-label-secondary">
                Source
                <select
                  data-testid="live-source"
                  value={source}
                  disabled={running}
                  onChange={(e) => setSource(e.target.value)}
                  className={`${control} min-w-0 max-w-[18rem] flex-1`}
                >
                  {canReplayDemo && <option value="replay:demo">Replay · bundled demo capture</option>}
                  {replayable.map((job) => (
                    <option key={job.job_id} value={`replay:${job.job_id}`}>
                      Replay · {jobLabel(job)}
                    </option>
                  ))}
                  {interfaces.map((nic) => (
                    <option key={nic.name} value={`nic:${nic.name}`}>
                      Interface · {nic.name}
                      {nic.description ? ` (${nic.description})` : ""}
                    </option>
                  ))}
                </select>
              </label>
              {source.startsWith("replay:") && (
                <label className="flex items-center gap-2 text-[length:var(--text-footnote)] text-label-secondary">
                  Speed
                  <select
                    data-testid="live-speed"
                    value={speed}
                    disabled={running}
                    onChange={(e) => setSpeed(Number(e.target.value))}
                    className={control}
                  >
                    {[10, 50, 200, 1000].map((x) => (
                      <option key={x} value={x}>
                        {x}×
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {running ? (
                <button
                  type="button"
                  data-testid="live-stop"
                  disabled={busy}
                  onClick={() => void stop()}
                  className="rounded-lg bg-critical px-3.5 py-1.5 text-[length:var(--text-footnote)] font-medium text-white disabled:opacity-40"
                >
                  Stop
                </button>
              ) : (
                <button
                  type="button"
                  data-testid="live-start"
                  disabled={busy}
                  onClick={() => void start()}
                  className="rounded-lg bg-accent px-3.5 py-1.5 text-[length:var(--text-footnote)] font-medium text-white hover:bg-[var(--accent-pressed)] disabled:opacity-40"
                >
                  Start capture
                </button>
              )}
            </div>

            <p
              data-testid="live-run-state"
              data-state={status.state}
              className="mt-3 text-[length:var(--text-footnote)] text-label-secondary"
            >
              {status.state === "idle" &&
                "No capture running. Replay needs no privileges; an interface needs dumpcap with capture rights on the backend host."}
              {status.state !== "idle" && (
                <>
                  <span className={running ? "text-low" : ""}>
                    {running ? "Capturing" : status.state === "error" ? "Failed" : "Finished"}
                  </span>{" "}
                  · {status.source} · {status.stats.packets.toLocaleString()} IPsec packets ·{" "}
                  {status.stats.sessions} sessions
                </>
              )}
            </p>
            {(error || status.error) && (
              <p role="alert" className="mt-2 text-[length:var(--text-footnote)] text-critical">
                {error ?? status.error}
              </p>
            )}
            {needsToken && (
              <OperatorToken
                onSaved={() => {
                  setNeedsToken(false);
                  setError(undefined);
                }}
              />
            )}
            {status.job_id && status.state !== "running" && status.state !== "idle" && (
              <button
                type="button"
                data-testid="live-open-job"
                onClick={() => {
                  select(status.job_id!);
                  router.push("/sessions");
                }}
                className="mt-3 text-[length:var(--text-footnote)] text-accent hover:underline"
              >
                Open this run in Sessions →
              </button>
            )}
          </section>

          <p className="mt-6 max-w-[62ch] text-[length:var(--text-footnote)] text-label-secondary">
            Sessions appear here the moment the backend finishes one, newest first — no reload, no
            polling. Analysing a capture in another tab shows up here too.
          </p>

          {anomalies.length > 0 && (
            <div className="mt-4 max-w-4xl">
              <AnomalyList
                anomalies={anomalies}
                compact
                onSelectSession={(id) => setSelected(sessions.find((s) => s.session_id === id) ?? null)}
              />
            </div>
          )}

          <div className="mt-5 w-full min-w-0 overflow-x-auto">
            {sessions.length === 0 ? (
              <p
                data-testid="live-empty"
                className="py-16 text-center text-[length:var(--text-subhead)] text-label-secondary"
              >
                {socket === "closed"
                  ? "The live stream is not connected. Start the backend and reload."
                  : "Waiting for the next session."}
              </p>
            ) : (
              <SessionTable
                sessions={sessions}
                onSelect={setSelected}
                selected={selected?.session_id}
                flagged={flagged}
              />
            )}
          </div>
        </div>

        {selected && (
          <SessionDrilldown
            session={selected}
            onClose={() => setSelected(null)}
            anomalies={anomalies.filter((a) => a.session_id === selected.session_id)}
          />
        )}
      </div>
    </div>
  );
}
