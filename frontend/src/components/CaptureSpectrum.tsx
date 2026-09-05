"use client";

import { SEVERITY_COLOR } from "@/lib/severity";
import { sortSessions } from "@/lib/sessions";
import type { VPNSession } from "@/lib/types";

/**
 * The whole capture as one strip: every session is a segment, ordered worst to
 * best. The shape of a capture -- mostly green with two red slivers, or half
 * red -- reads before any individual row does.
 */
export function CaptureSpectrum({
  sessions,
  onSelect,
  selected,
}: {
  sessions: VPNSession[];
  onSelect: (sessionId: string) => void;
  selected?: string;
}) {
  if (sessions.length === 0) return null;
  const ordered = sortSessions(sessions, "risk");

  return (
    <div data-testid="capture-spectrum" className="flex h-9 gap-px overflow-hidden rounded-md">
      {ordered.map((session) => {
        const severity = session.security_assessment.overall_severity;
        const active = session.session_id === selected;
        return (
          <button
            key={session.session_id}
            type="button"
            onClick={() => onSelect(session.session_id)}
            title={`${session.initiator_ip} → ${session.responder_ip} · ${severity} · score ${session.security_assessment.risk_score}`}
            aria-label={`Session ${session.session_id}, ${severity}`}
            className="min-w-[3px] max-w-[5rem] flex-1 transition-opacity hover:opacity-100"
            style={{
              background: SEVERITY_COLOR[severity],
              opacity: active ? 1 : 0.72,
              outline: active ? "2px solid var(--label)" : undefined,
              outlineOffset: "-2px",
            }}
          />
        );
      })}
    </div>
  );
}
