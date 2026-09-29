"use client";

import { useEffect, useState } from "react";
import { liveSocketUrl } from "./api";
import type { AnomalyEvent, LiveMessage, LiveStatus, VPNSession } from "./types";

export type SocketState = "connecting" | "open" | "closed";

const IDLE: LiveStatus = {
  state: "idle",
  job_id: null,
  source: null,
  started_at: null,
  stats: {
    packets: 0,
    ike_packets: 0,
    esp_packets: 0,
    duration_sec: 0,
    sessions: 0,
    incomplete_sessions: 0,
    orphan_esp_packets: 0,
  },
  error: null,
};

/**
 * Everything /ws/live says (P4-T7): sessions and anomalies as the backend
 * finds them -- from any upload or live run -- plus the live run's status.
 *
 * Newest first, deduplicated: a live run re-analyses its growing capture every
 * tick, and an SA that gained packets replaces its row rather than adding one.
 * An SA first seen mid-handshake changes id when its responder SPI appears;
 * the backend retracts the old id with a ``session_removed`` message.
 * The socket is opened once and closed on unmount -- React double-invokes
 * effects in development, and a socket left open there would double every event.
 */
export function useLive() {
  const [sessions, setSessions] = useState<VPNSession[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>([]);
  const [status, setStatus] = useState<LiveStatus>(IDLE);
  const [socket, setSocket] = useState<SocketState>("connecting");

  useEffect(() => {
    const ws = new WebSocket(liveSocketUrl());
    ws.onopen = () => setSocket("open");
    ws.onclose = () => setSocket("closed");
    ws.onerror = () => setSocket("closed");
    ws.onmessage = (event) => {
      let message: LiveMessage;
      try {
        message = JSON.parse(event.data as string) as LiveMessage;
      } catch {
        return; // a malformed frame is not worth tearing the stream down for
      }
      if (message.type === "session") {
        const incoming = message.session;
        setSessions((current) => [
          incoming,
          ...current.filter((s) => s.session_id !== incoming.session_id),
        ]);
      } else if (message.type === "session_removed") {
        const gone = message.session_id;
        setSessions((current) => current.filter((s) => s.session_id !== gone));
      } else if (message.type === "anomaly") {
        const incoming = message.anomaly;
        setAnomalies((current) => [
          incoming,
          ...current.filter((a) => a.anomaly_id !== incoming.anomaly_id),
        ]);
      } else if (message.type === "live") {
        setStatus(message.status);
      }
    };
    return () => {
      ws.onclose = null;
      ws.close();
    };
  }, []);

  return {
    sessions,
    anomalies,
    status,
    socket,
    clear: () => {
      setSessions([]);
      setAnomalies([]);
    },
  };
}
