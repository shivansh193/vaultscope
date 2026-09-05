"use client";

import { useEffect, useState } from "react";
import { API_BASE, health } from "@/lib/api";
import type { Health } from "@/lib/types";

type State = { kind: "checking" } | { kind: "up"; health: Health } | { kind: "down"; why: string };

/** P4-T1's done criterion: the app says, out loud, whether the backend is there. */
export function BackendStatus() {
  const [state, setState] = useState<State>({ kind: "checking" });

  useEffect(() => {
    let cancelled = false;
    health()
      .then((h) => !cancelled && setState({ kind: "up", health: h }))
      .catch((error: Error) => !cancelled && setState({ kind: "down", why: error.message }));
    return () => {
      cancelled = true;
    };
  }, []);

  const dot =
    state.kind === "up"
      ? "var(--severity-low)"
      : state.kind === "down"
        ? "var(--severity-critical)"
        : "var(--label-tertiary)";

  return (
    <div data-testid="backend-status" data-state={state.kind} className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <span aria-hidden className="h-2 w-2 shrink-0 rounded-full" style={{ background: dot }} />
        <span className="text-[length:var(--text-footnote)] text-label-secondary">
          {state.kind === "checking" && "Connecting to backend"}
          {state.kind === "up" && `Backend ${state.health.version}`}
          {state.kind === "down" && "Backend unreachable"}
        </span>
      </div>
      <p className="pl-4 text-[length:var(--text-caption)] leading-snug text-label-tertiary">
        {state.kind === "up" &&
          (state.health.parser_available
            ? "IKE parser ready"
            : "No IKE parser — results come from fixtures")}
        {state.kind === "down" && `Start it with uvicorn api.main:app, then reload. ${API_BASE}`}
      </p>
    </div>
  );
}
