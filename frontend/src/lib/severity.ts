/** Severity is read by hue everywhere in the console; the mapping lives here. */

import type { Severity } from "./types";

export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--severity-critical)",
  HIGH: "var(--severity-high)",
  MEDIUM: "var(--severity-medium)",
  LOW: "var(--severity-low)",
  SAFE: "var(--severity-safe)",
};

const RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, SAFE: 4 };

/** Worst severity first. Sorting by this puts what needs attention on top. */
export const bySeverity = (a: Severity, b: Severity) => RANK[a] - RANK[b];

export const worst = (severities: Severity[]): Severity =>
  severities.length === 0 ? "SAFE" : [...severities].sort(bySeverity)[0];
