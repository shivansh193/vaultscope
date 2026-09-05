"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { TRAFFIC_COLOR, trafficMix } from "@/lib/charts";
import type { VPNSession } from "@/lib/types";
import { cellClass, ChartFrame } from "./ChartFrame";

/**
 * Traffic type is categorical: each type owns its hue by slot, so a capture
 * without VoIP does not repaint Web in VoIP's colour.
 */
export function TrafficMix({ sessions }: { sessions: VPNSession[] }) {
  const mix = trafficMix(sessions);
  // Stage 4b is Block A's; until a trained model lands every session comes back
  // "Other" at zero confidence. Saying so beats drawing a confident-looking
  // donut of one slice.
  const untrained =
    sessions.length > 0 &&
    sessions.every((s) => ["untrained", "fixture"].includes(s.traffic_prediction.model_version));
  const total = mix.reduce((sum, slice) => sum + slice.count, 0);
  const share = (count: number) => (total ? Math.round((count / total) * 100) : 0);

  return (
    <ChartFrame
      title="Traffic inside the tunnels"
      note="Inferred from ESP packet sizes and timing alone. The payloads stay encrypted, so these are predictions, not observations."
      table={
        <table>
          <thead>
            <tr className="text-left text-label-secondary">
              <th className={cellClass}>Type</th>
              <th className={cellClass}>Sessions</th>
              <th className={cellClass}>Share</th>
            </tr>
          </thead>
          <tbody>
            {mix.map((slice) => (
              <tr key={slice.type}>
                <td className={cellClass}>{slice.type}</td>
                <td className={`${cellClass} tabular`}>{slice.count}</td>
                <td className={`${cellClass} tabular`}>{share(slice.count)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      {untrained && (
        <p className="mb-4 rounded-lg bg-surface-raised px-3 py-2 text-[length:var(--text-footnote)] text-label-secondary">
          No trained classifier yet, so every session is reported as Other. These are placeholders,
          not predictions.
        </p>
      )}
      {mix.length === 0 ? (
        <p className="py-16 text-center text-[length:var(--text-subhead)] text-label-secondary">
          No traffic predictions yet.
        </p>
      ) : (
        <div className="flex flex-wrap items-center gap-6">
          <ResponsiveContainer width={220} height={220}>
            <PieChart>
              <Pie
                data={mix}
                dataKey="count"
                nameKey="type"
                innerRadius={58}
                outerRadius={92}
                paddingAngle={2}
                stroke="var(--surface)"
                strokeWidth={2}
              >
                {mix.map((slice) => (
                  <Cell key={slice.type} fill={TRAFFIC_COLOR[slice.type]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#2c2c2e",
                  border: "1px solid #38383a",
                  borderRadius: 8,
                  fontSize: 12,
                }}
                formatter={(value, name) => [`${value ?? 0} sessions`, `${name}`]}
              />
            </PieChart>
          </ResponsiveContainer>

          <ul className="flex flex-col gap-1.5 text-[length:var(--text-footnote)]">
            {mix.map((slice) => (
              <li key={slice.type} className="flex items-center gap-2">
                <span
                  aria-hidden
                  className="h-2.5 w-2.5 rounded-[2px]"
                  style={{ background: TRAFFIC_COLOR[slice.type] }}
                />
                <span>{slice.type}</span>
                <span className="tabular text-label-tertiary">{share(slice.count)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </ChartFrame>
  );
}
