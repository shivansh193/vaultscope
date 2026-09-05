"use client";

import { IMPACT, LIKELIHOOD, rampStep, threatMatrix } from "@/lib/charts";
import type { VPNSession } from "@/lib/types";
import { cellClass, ChartFrame } from "./ChartFrame";

/** Sequential, one hue: a cell encodes only how many threats land in it. */
export function ThreatMatrix({ sessions }: { sessions: VPNSession[] }) {
  const cells = threatMatrix(sessions);
  const max = Math.max(0, ...cells.map((cell) => cell.count));
  const at = (likelihood: string, impact: string) =>
    cells.find((cell) => cell.likelihood === likelihood && cell.impact === impact);

  return (
    <ChartFrame
      title="Threat matrix"
      note="Every threat raised across the capture, placed by how likely it is and how much it would cost."
      table={
        <table>
          <thead>
            <tr className="text-left text-label-secondary">
              <th className={cellClass}>Likelihood</th>
              <th className={cellClass}>Impact</th>
              <th className={cellClass}>Threats</th>
              <th className={cellClass}>Count</th>
            </tr>
          </thead>
          <tbody>
            {cells.map((cell) => (
              <tr key={`${cell.likelihood}/${cell.impact}`}>
                <td className={cellClass}>{cell.likelihood}</td>
                <td className={cellClass}>{cell.impact}</td>
                <td className={cellClass}>{cell.threats.join(", ") || "—"}</td>
                <td className={`${cellClass} tabular`}>{cell.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      <div className="grid grid-cols-[auto_repeat(3,1fr)] gap-1.5">
        <span />
        {LIKELIHOOD.map((likelihood) => (
          <span
            key={likelihood}
            className="pb-1 text-center text-[length:var(--text-caption)] text-label-secondary"
          >
            {likelihood} likelihood
          </span>
        ))}

        {IMPACT.map((impact) => (
          <div key={impact} className="contents">
            <span className="self-center pr-2 text-right text-[length:var(--text-caption)] text-label-secondary">
              {impact} impact
            </span>
            {LIKELIHOOD.map((likelihood) => {
              const cell = at(likelihood, impact);
              const count = cell?.count ?? 0;
              return (
                <div
                  key={`${likelihood}/${impact}`}
                  data-testid="matrix-cell"
                  title={cell?.threats.join(", ") || "No threats in this cell"}
                  className="flex h-16 items-center justify-center rounded-lg"
                  style={{ background: rampStep(count, max) }}
                >
                  <span
                    className={`tabular text-[length:var(--text-title-3)] font-semibold ${
                      count === 0 ? "text-label-tertiary" : "text-white"
                    }`}
                  >
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </ChartFrame>
  );
}
