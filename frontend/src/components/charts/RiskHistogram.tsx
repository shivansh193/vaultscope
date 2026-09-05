"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { riskHistogram } from "@/lib/charts";
import type { VPNSession } from "@/lib/types";
import { cellClass, ChartFrame } from "./ChartFrame";

const AXIS = { stroke: "#636366", fontSize: 11 };

const TOOLTIP = {
  background: "#2c2c2e",
  border: "1px solid #38383a",
  borderRadius: 8,
  fontSize: 12,
};

/**
 * One series, so one hue -- the bars are deliberately not coloured by
 * severity, because a score band is not a severity: a CRITICAL rule pins the
 * severity regardless of where the score lands, and colouring the bands would
 * imply a mapping that does not exist.
 */
export function RiskHistogram({ sessions }: { sessions: VPNSession[] }) {
  const bins = riskHistogram(sessions);

  return (
    <ChartFrame
      title="Risk distribution"
      note="Sessions per ten-point band of composite risk score. Higher is healthier."
      table={
        <table>
          <thead>
            <tr className="text-left text-label-secondary">
              <th className={cellClass}>Band</th>
              <th className={cellClass}>Sessions</th>
            </tr>
          </thead>
          <tbody>
            {bins.map((bin) => (
              <tr key={bin.band}>
                <td className={`${cellClass} mono`}>{bin.band}</td>
                <td className={`${cellClass} tabular`}>{bin.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={bins} margin={{ top: 4, right: 4, bottom: 0, left: -22 }}>
          <CartesianGrid stroke="#2c2c2e" vertical={false} />
          <XAxis dataKey="band" tickLine={false} axisLine={false} tick={AXIS} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={AXIS} />
          <Tooltip
            cursor={{ fill: "#2c2c2e" }}
            contentStyle={TOOLTIP}
            labelStyle={{ color: "#f5f5f7" }}
            formatter={(value) => [`${value ?? 0}`, "sessions"]}
          />
          <Bar dataKey="count" fill="var(--ramp-3)" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartFrame>
  );
}
