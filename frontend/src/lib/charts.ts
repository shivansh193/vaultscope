/**
 * Shared chart vocabulary.
 *
 * Traffic types are categorical: each type owns a hue by slot, fixed order,
 * never cycled -- a filter that removes a type must not repaint the others.
 * Severity is a status scale and keeps its own hues (see severity.ts); the two
 * never appear in the same chart.
 */

import type { Severity, TrafficType, VPNSession } from "./types";

export const TRAFFIC_ORDER: TrafficType[] = [
  "VoIP",
  "Video",
  "Web",
  "Email",
  "ICMP",
  "Chat",
  "Other",
];

export const TRAFFIC_COLOR: Record<TrafficType, string> = {
  VoIP: "var(--traffic-voip)",
  Video: "var(--traffic-video)",
  Web: "var(--traffic-web)",
  Email: "var(--traffic-email)",
  ICMP: "var(--traffic-icmp)",
  Chat: "var(--traffic-chat)",
  Other: "var(--traffic-other)",
};

export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: "#FF453A",
  HIGH: "#FF9F0A",
  MEDIUM: "#FFD60A",
  LOW: "#30D158",
  SAFE: "#48484A",
};

/** Risk scores bucketed into ten bands, so the histogram has stable bins. */
export function riskHistogram(sessions: VPNSession[]): { band: string; count: number }[] {
  const bins = Array.from({ length: 10 }, (_, i) => ({
    band: `${i * 10}–${i * 10 + 9}`,
    count: 0,
  }));
  for (const session of sessions) {
    const score = Math.max(0, Math.min(100, session.security_assessment.risk_score));
    bins[Math.min(9, Math.floor(score / 10))].count += 1;
  }
  return bins;
}

export function trafficMix(sessions: VPNSession[]): { type: TrafficType; count: number }[] {
  const counts = new Map<TrafficType, number>();
  for (const session of sessions) {
    const type = session.traffic_prediction.predicted_type;
    counts.set(type, (counts.get(type) ?? 0) + 1);
  }
  return TRAFFIC_ORDER.filter((type) => counts.has(type)).map((type) => ({
    type,
    count: counts.get(type) as number,
  }));
}

export const LIKELIHOOD: ("Low" | "Med" | "High")[] = ["Low", "Med", "High"];
export const IMPACT: ("Low" | "Med" | "High")[] = ["High", "Med", "Low"];

export interface MatrixCell {
  likelihood: "Low" | "Med" | "High";
  impact: "Low" | "Med" | "High";
  count: number;
  threats: string[];
}

/** Threats across the capture, counted into the 3x3 likelihood/impact grid. */
export function threatMatrix(sessions: VPNSession[]): MatrixCell[] {
  const cells = new Map<string, MatrixCell>();
  for (const impact of IMPACT) {
    for (const likelihood of LIKELIHOOD) {
      cells.set(`${likelihood}/${impact}`, { likelihood, impact, count: 0, threats: [] });
    }
  }
  for (const session of sessions) {
    for (const entry of session.security_assessment.threat_matrix) {
      const cell = cells.get(`${entry.likelihood}/${entry.impact}`);
      if (!cell) continue;
      cell.count += 1;
      if (!cell.threats.includes(entry.threat)) cell.threats.push(entry.threat);
    }
  }
  return [...cells.values()];
}

/** Sequential ramp step for a count, relative to the busiest cell. */
export function rampStep(count: number, max: number): string {
  if (count === 0) return "var(--surface-raised)";
  const share = max === 0 ? 0 : count / max;
  if (share > 0.8) return "var(--ramp-1)";
  if (share > 0.6) return "var(--ramp-2)";
  if (share > 0.4) return "var(--ramp-3)";
  if (share > 0.2) return "var(--ramp-4)";
  return "var(--ramp-5)";
}

export interface PeerNode {
  id: string;
  severity: Severity;
  sessions: number;
}

export interface PeerEdge {
  source: string;
  target: string;
  sessionId: string;
  severity: Severity;
}

/** Peers and the sessions between them: the force graph's whole input. */
export function peerGraph(sessions: VPNSession[]): { nodes: PeerNode[]; edges: PeerEdge[] } {
  const rank: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, SAFE: 4 };
  const nodes = new Map<string, PeerNode>();
  const edges: PeerEdge[] = [];

  const touch = (ip: string, severity: Severity) => {
    const existing = nodes.get(ip);
    if (!existing) nodes.set(ip, { id: ip, severity, sessions: 1 });
    else {
      existing.sessions += 1;
      if (rank[severity] < rank[existing.severity]) existing.severity = severity;
    }
  };

  for (const session of sessions) {
    const severity = session.security_assessment.overall_severity;
    const { initiator_ip: from, responder_ip: to } = session;
    if (!from || !to) continue;
    touch(from, severity);
    touch(to, severity);
    edges.push({ source: from, target: to, sessionId: session.session_id, severity });
  }

  return { nodes: [...nodes.values()], edges };
}
