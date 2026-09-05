"use client";

import { SEVERITY_COLOR } from "@/lib/severity";
import type { SortDirection, SortKey } from "@/lib/sessions";
import type { VPNSession } from "@/lib/types";

/** CRITICAL rows are tinted, not badged: the eye finds them scanning the column. */
const ROW_TINT: Partial<Record<string, string>> = {
  CRITICAL: "rgba(255, 69, 58, 0.12)",
  HIGH: "rgba(255, 159, 10, 0.07)",
};

const COLUMNS: { key: SortKey | null; label: string; testId?: string }[] = [
  { key: "risk", label: "Risk", testId: "sort-risk" },
  { key: "peer", label: "Peers", testId: "sort-peer" },
  { key: "version", label: "IKE", testId: "sort-version" },
  { key: "cipher", label: "Encryption", testId: "sort-cipher" },
  { key: null, label: "DH group" },
  { key: null, label: "PFS" },
  { key: null, label: "Traffic" },
  { key: null, label: "Findings" },
];

export function SessionTable({
  sessions,
  sort,
  direction,
  onSort,
  onSelect,
  selected,
}: {
  sessions: VPNSession[];
  sort: SortKey;
  direction: SortDirection;
  onSort: (key: SortKey) => void;
  onSelect: (session: VPNSession) => void;
  selected?: string;
}) {
  if (sessions.length === 0) {
    return (
      <p className="px-1 py-16 text-center text-[length:var(--text-subhead)] text-label-secondary">
        No sessions match these filters. Widen them, or analyse another capture.
      </p>
    );
  }

  return (
    <table className="w-full min-w-[54rem] border-collapse text-[length:var(--text-subhead)]">
      <thead>
        <tr className="border-b border-separator text-left text-label-secondary">
          {COLUMNS.map(({ key, label, testId }) => (
            <th
              key={label}
              scope="col"
              aria-sort={
                key && sort === key ? (direction === "asc" ? "ascending" : "descending") : undefined
              }
              className="py-2 pr-4 font-normal first:pl-3"
            >
              {key ? (
                <button
                  type="button"
                  data-testid={testId}
                  onClick={() => onSort(key)}
                  className="inline-flex items-center gap-1 hover:text-label"
                >
                  {label}
                  <span aria-hidden className={sort === key ? "text-accent" : "text-transparent"}>
                    {direction === "asc" ? "↑" : "↓"}
                  </span>
                </button>
              ) : (
                label
              )}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {sessions.map((session) => {
          const { overall_severity: severity, risk_score, findings } = session.security_assessment;
          const active = session.session_id === selected;
          return (
            <tr
              key={session.session_id}
              data-testid="session-row"
              data-id={session.session_id}
              data-severity={severity}
              onClick={() => onSelect(session)}
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onSelect(session)}
              style={{ background: ROW_TINT[severity] }}
              className={`cursor-pointer border-b border-separator/60 transition-colors hover:brightness-125 ${
                active ? "shadow-[inset_0_0_0_1px_var(--accent)]" : ""
              }`}
            >
              <td className="relative py-2.5 pl-3 pr-4">
                <span
                  aria-hidden
                  className="absolute inset-y-0 left-0 w-[2px]"
                  style={{ background: SEVERITY_COLOR[severity] }}
                />
                <span className="tabular font-medium" data-field="risk_score">
                  {risk_score}
                </span>
                <span className="ml-2 text-label-tertiary">{severity}</span>
              </td>
              <td className="whitespace-nowrap py-2.5 pr-4">
                <span className="mono" data-field="initiator_ip">
                  {session.initiator_ip || "—"}
                </span>
                <span aria-hidden className="mx-1.5 text-label-tertiary">
                  →
                </span>
                <span className="mono" data-field="responder_ip">
                  {session.responder_ip || "—"}
                </span>
              </td>
              <td className="whitespace-nowrap py-2.5 pr-4" data-field="ike_version">
                {session.ike.version}
                {session.ike.aggressive_mode && (
                  <span className="ml-1.5 text-critical">Aggressive</span>
                )}
              </td>
              <td className="mono whitespace-nowrap py-2.5 pr-4" data-field="encryption">
                {session.ike.encryption}
              </td>
              <td className="mono whitespace-nowrap py-2.5 pr-4" data-field="dh_group">
                {session.ike.dh_group}
              </td>
              <td className="py-2.5 pr-4 text-label-secondary" data-field="pfs_status">
                {session.ike.pfs_status}
              </td>
              <td className="py-2.5 pr-4" data-field="traffic_type">
                {session.traffic_prediction.predicted_type}
                <span className="ml-1.5 tabular text-label-tertiary">
                  {Math.round(session.traffic_prediction.confidence * 100)}%
                </span>
              </td>
              <td className="tabular py-2.5 pr-4 text-label-secondary" data-field="finding_count">
                {findings.length}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
