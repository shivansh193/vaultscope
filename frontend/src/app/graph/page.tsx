"use client";

import { useRouter } from "next/navigation";
import { useCallback, useMemo } from "react";
import { PeerGraph } from "@/components/PeerGraph";
import { Toolbar } from "@/components/Toolbar";
import { peerGraph, SEVERITY_HEX } from "@/lib/charts";
import { SEVERITY_ORDER } from "@/lib/types";
import { useSessions } from "@/lib/useSessions";

export default function GraphPage() {
  const router = useRouter();
  const { sessions, loading, error } = useSessions();
  const { nodes, edges } = useMemo(() => peerGraph(sessions), [sessions]);

  const selectPeer = useCallback(
    (ip: string) => router.push(`/sessions?peer=${encodeURIComponent(ip)}`),
    [router],
  );
  const selectSession = useCallback(
    (sessionId: string) => router.push(`/sessions?session=${encodeURIComponent(sessionId)}`),
    [router],
  );

  return (
    <div className="flex h-screen flex-col">
      <Toolbar title="Peers" />

      <div className="flex min-h-0 flex-1 flex-col px-7 py-6">
        <div className="flex flex-wrap items-baseline justify-between gap-x-8 gap-y-2">
          <p className="max-w-[62ch] text-[length:var(--text-footnote)] text-label-secondary">
            Each node is a peer address, sized by how many sessions it carries and coloured by its
            worst one. Drag to rearrange, click a peer to filter the table to it, click a session
            line to open it.
          </p>
          <ul className="flex items-center gap-3 text-[length:var(--text-caption)] text-label-secondary">
            {SEVERITY_ORDER.map((severity) => (
              <li key={severity} className="flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="h-2 w-2 rounded-full"
                  style={{ background: SEVERITY_HEX[severity] }}
                />
                {severity}
              </li>
            ))}
          </ul>
        </div>

        <div className="mt-4 min-h-0 flex-1 rounded-xl border border-separator bg-surface">
          {loading && (
            <p className="p-16 text-center text-[length:var(--text-subhead)] text-label-secondary">
              Loading peers
            </p>
          )}
          {error && (
            <p role="alert" className="p-16 text-center text-[length:var(--text-subhead)] text-critical">
              Peers could not be loaded. {error}
            </p>
          )}
          {!loading && !error && nodes.length === 0 && (
            <p className="p-16 text-center text-[length:var(--text-subhead)] text-label-secondary">
              No peers yet. Analyse a capture and they appear here.
            </p>
          )}
          {!loading && !error && nodes.length > 0 && (
            <PeerGraph
              nodes={nodes}
              edges={edges}
              onSelectPeer={selectPeer}
              onSelectSession={selectSession}
            />
          )}
        </div>
      </div>
    </div>
  );
}
