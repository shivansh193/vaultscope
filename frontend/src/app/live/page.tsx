"use client";

import { useState } from "react";
import { SessionDrilldown } from "@/components/SessionDrilldown";
import { SessionTable } from "@/components/SessionTable";
import { Toolbar } from "@/components/Toolbar";
import { useLiveSessions } from "@/lib/useLiveSessions";
import type { VPNSession } from "@/lib/types";

const STATE_LABEL = {
  connecting: "Connecting",
  open: "Listening",
  closed: "Disconnected",
} as const;

const STATE_COLOR = {
  connecting: "var(--label-tertiary)",
  open: "var(--severity-low)",
  closed: "var(--severity-critical)",
} as const;

export default function LivePage() {
  const { sessions, state, clear } = useLiveSessions();
  const [selected, setSelected] = useState<VPNSession | null>(null);

  return (
    <div className="flex h-screen flex-col">
      <Toolbar title="Live">
        <span
          data-testid="live-state"
          data-state={state}
          className="flex items-center gap-2 text-[length:var(--text-footnote)] text-label-secondary"
        >
          <span
            aria-hidden
            className="h-2 w-2 rounded-full"
            style={{ background: STATE_COLOR[state] }}
          />
          {STATE_LABEL[state]}
        </span>
        <button
          type="button"
          onClick={clear}
          disabled={sessions.length === 0}
          className="rounded-md border border-separator bg-surface-raised px-2.5 py-1.5 text-[length:var(--text-footnote)] text-label disabled:opacity-35"
        >
          Clear
        </button>
      </Toolbar>

      <div className="flex min-h-0 w-full flex-1 overflow-hidden">
        <div className="w-0 flex-1 overflow-y-auto px-7 py-6">
          <p className="max-w-[62ch] text-[length:var(--text-footnote)] text-label-secondary">
            Sessions appear here the moment the backend finishes one, newest first — no reload, no
            polling. Analysing a capture in another tab shows up here too.
          </p>

          <div className="mt-5 w-full min-w-0 overflow-x-auto">
            {sessions.length === 0 ? (
              <p
                data-testid="live-empty"
                className="py-16 text-center text-[length:var(--text-subhead)] text-label-secondary"
              >
                {state === "closed"
                  ? "The live stream is not connected. Start the backend and reload."
                  : "Waiting for the next session."}
              </p>
            ) : (
              <SessionTable
                sessions={sessions}
                onSelect={setSelected}
                selected={selected?.session_id}
              />
            )}
          </div>
        </div>

        {selected && <SessionDrilldown session={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}
