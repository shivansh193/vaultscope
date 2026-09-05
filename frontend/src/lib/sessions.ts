/**
 * Sorting, filtering and paging for the session table.
 *
 * Kept out of the component so the table's behaviour can be tested without
 * rendering, and so the peer graph can reuse the same filters.
 */

import { bySeverity } from "./severity";
import type { Severity, VPNSession } from "./types";

export type SortKey = "risk" | "cipher" | "peer" | "version";
export type SortDirection = "asc" | "desc";

export interface Filters {
  ikeVersion?: "IKEv1" | "IKEv2";
  severity?: Severity;
  peer?: string;
  search?: string;
}

const PEER = (s: VPNSession) => `${s.initiator_ip} ${s.responder_ip}`;

const COMPARE: Record<SortKey, (a: VPNSession, b: VPNSession) => number> = {
  // Worst first: a risk sort exists to surface what is wrong, not to rank the healthy.
  risk: (a, b) =>
    bySeverity(a.security_assessment.overall_severity, b.security_assessment.overall_severity) ||
    a.security_assessment.risk_score - b.security_assessment.risk_score,
  cipher: (a, b) => a.ike.encryption.localeCompare(b.ike.encryption),
  peer: (a, b) => compareIp(a.initiator_ip, b.initiator_ip),
  version: (a, b) => a.ike.version.localeCompare(b.ike.version),
};

/** Sort IPv4 numerically so .9 precedes .10; anything else falls back to text. */
function compareIp(a: string, b: string): number {
  const parse = (ip: string) => ip.split(".").map(Number);
  const [x, y] = [parse(a), parse(b)];
  if (x.length !== 4 || y.length !== 4 || [...x, ...y].some(Number.isNaN)) {
    return a.localeCompare(b);
  }
  for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

export function sortSessions(
  sessions: VPNSession[],
  key: SortKey,
  direction: SortDirection = "asc",
): VPNSession[] {
  const sorted = [...sessions].sort(COMPARE[key]);
  return direction === "asc" ? sorted : sorted.reverse();
}

export function filterSessions(sessions: VPNSession[], filters: Filters): VPNSession[] {
  const needle = filters.search?.trim().toLowerCase();
  return sessions.filter((session) => {
    if (filters.ikeVersion && session.ike.version !== filters.ikeVersion) return false;
    if (filters.severity && session.security_assessment.overall_severity !== filters.severity) {
      return false;
    }
    if (filters.peer && !PEER(session).includes(filters.peer)) return false;
    if (needle) {
      const haystack = [
        session.session_id,
        PEER(session),
        session.ike.encryption,
        session.ike.dh_group,
        session.ike.vendor,
        session.traffic_prediction.predicted_type,
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(needle)) return false;
    }
    return true;
  });
}

export const pageCount = (total: number, perPage: number) =>
  Math.max(1, Math.ceil(total / perPage));

export const page = <T>(items: T[], pageIndex: number, perPage: number): T[] =>
  items.slice(pageIndex * perPage, pageIndex * perPage + perPage);

/** Every distinct peer address in the capture, in first-seen order. */
export function peers(sessions: VPNSession[]): string[] {
  const seen = new Set<string>();
  for (const session of sessions) {
    if (session.initiator_ip) seen.add(session.initiator_ip);
    if (session.responder_ip) seen.add(session.responder_ip);
  }
  return [...seen];
}
