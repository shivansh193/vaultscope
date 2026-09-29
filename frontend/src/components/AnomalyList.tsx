"use client";

import { captureUrl } from "@/lib/api";
import { SEVERITY_COLOR } from "@/lib/severity";
import type { AnomalyEvent } from "@/lib/types";

/** "AGGRESSIVE_MODE_PROBE" -> "Aggressive mode probe"; acronyms stay acronyms. */
export const anomalyTitle = (kind: string) =>
  (kind.charAt(0) + kind.slice(1).toLowerCase().replace(/_/g, " "))
    .replace(/^Nat t\b/, "NAT-T")
    .replace(/^Spi\b/, "SPI");

function frames(evidence: number[]): string {
  if (evidence.length === 0) return "no frame evidence";
  const shown = evidence.slice(0, 8).join(", ");
  return `frame${evidence.length === 1 ? "" : "s"} ${shown}${evidence.length > 8 ? ", …" : ""}`;
}

interface Group {
  kind: string;
  severity: AnomalyEvent["severity"];
  events: AnomalyEvent[];
  frames: number[];
  sessions: string[];
}

const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 } as const;

/** One card per anomaly type: a scanner trips the same detector once per SA it touched. */
export function groupAnomalies(anomalies: AnomalyEvent[]): Group[] {
  const groups = new Map<string, Group>();
  for (const event of anomalies) {
    const group = groups.get(event.anomaly_type) ?? {
      kind: event.anomaly_type,
      severity: event.severity,
      events: [],
      frames: [],
      sessions: [],
    };
    group.events.push(event);
    if (RANK[event.severity] < RANK[group.severity]) group.severity = event.severity;
    group.frames.push(...event.evidence_pkts);
    if (!group.sessions.includes(event.session_id)) group.sessions.push(event.session_id);
    groups.set(event.anomaly_type, group);
  }
  for (const group of groups.values()) group.frames = [...new Set(group.frames)].sort((a, b) => a - b);
  return [...groups.values()].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
}

/**
 * Runtime attack indicators, grouped by kind, with the pcap frames that prove them.
 *
 * Every card names frame numbers in the capture this job analysed; the link
 * downloads that exact file, so a reviewer can open it in Wireshark, Go to
 * Packet, and see the evidence for themselves.
 */
export function AnomalyList({
  anomalies,
  jobId,
  captureAvailable,
  onSelectSession,
  compact = false,
}: {
  anomalies: AnomalyEvent[];
  jobId?: string;
  captureAvailable?: boolean;
  onSelectSession?: (sessionId: string) => void;
  compact?: boolean;
}) {
  if (anomalies.length === 0) return null;

  return (
    <div data-testid="anomaly-list">
      <ul className="flex flex-col gap-2">
        {groupAnomalies(anomalies).map((group) => {
          const first = group.events[0];
          return (
            <li
              key={group.kind}
              data-testid="anomaly"
              data-type={group.kind}
              className="flex gap-3 rounded-lg border border-separator bg-surface px-3 py-2.5"
            >
              <span
                aria-hidden
                className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                style={{ background: SEVERITY_COLOR[group.severity] }}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="text-[length:var(--text-footnote)] font-semibold">
                    {anomalyTitle(group.kind)}
                  </span>
                  <span
                    className="text-[length:var(--text-caption)]"
                    style={{ color: SEVERITY_COLOR[group.severity] }}
                  >
                    {group.severity}
                  </span>
                  {group.sessions.length > 1 && (
                    <span className="text-[length:var(--text-caption)] text-label-tertiary">
                      {group.sessions.length} sessions
                    </span>
                  )}
                </div>
                {!compact && (
                  <p className="mt-0.5 text-[length:var(--text-footnote)] text-label-secondary">
                    {first.description}
                  </p>
                )}
                <p className="mono mt-1 text-[length:var(--text-caption)] text-label-tertiary">
                  <span data-testid="evidence-frames">{frames(group.frames)}</span>
                  {first.timestamp && ` · ${first.timestamp.replace("T", " ").slice(0, 19)}`}
                </p>
                {onSelectSession && (
                  <p className="mt-1 flex flex-wrap gap-x-3 text-[length:var(--text-caption)]">
                    {group.sessions.slice(0, 6).map((id, n) => (
                      <button
                        key={id}
                        type="button"
                        onClick={() => onSelectSession(id)}
                        className="text-accent hover:underline"
                      >
                        {group.sessions.length === 1 ? "open session" : `session ${n + 1}`}
                      </button>
                    ))}
                    {group.sessions.length > 6 && (
                      <span className="text-label-tertiary">+{group.sessions.length - 6} more</span>
                    )}
                  </p>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      {jobId && captureAvailable && (
        <a
          data-testid="download-capture"
          href={captureUrl(jobId)}
          className="mt-2 inline-block text-[length:var(--text-caption)] text-accent hover:underline"
        >
          Download the capture to verify these frames in Wireshark
        </a>
      )}
    </div>
  );
}
