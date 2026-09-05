"use client";

import { useEffect, useRef, useState } from "react";
import { liveSocketUrl } from "./api";
import type { VPNSession } from "./types";

export type LiveState = "connecting" | "open" | "closed";

/**
 * Sessions as the backend detects them (P4-T7).
 *
 * Newest first, deduplicated by session_id: a re-analysis of the same SA
 * replaces its row rather than adding a second one. The socket is opened once
 * per nic and closed on unmount -- React 18 double-invokes effects in
 * development, and a socket left open there would double every event.
 */
export function useLiveSessions(nic?: string) {
  const [sessions, setSessions] = useState<VPNSession[]>([]);
  const [state, setState] = useState<LiveState>("connecting");
  const socketRef = useRef<WebSocket>(null);

  useEffect(() => {
    const socket = new WebSocket(liveSocketUrl(nic));
    socketRef.current = socket;

    socket.onopen = () => setState("open");
    socket.onclose = () => setState("closed");
    socket.onerror = () => setState("closed");
    socket.onmessage = (event) => {
      let session: VPNSession;
      try {
        session = JSON.parse(event.data as string) as VPNSession;
      } catch {
        return; // a malformed frame is not worth tearing the stream down for
      }
      if (!session?.session_id) return;
      setSessions((current) => [
        session,
        ...current.filter((s) => s.session_id !== session.session_id),
      ]);
    };

    return () => {
      socket.onclose = null;
      socket.close();
    };
  }, [nic]);

  return { sessions, state, clear: () => setSessions([]) };
}
