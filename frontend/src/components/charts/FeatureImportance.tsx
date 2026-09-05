"use client";

import { useEffect, useState } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { modelMetrics } from "@/lib/api";
import type { ModelMetrics } from "@/lib/types";
import { cellClass, ChartFrame } from "./ChartFrame";

/**
 * Which Stage 3 features the traffic classifier actually leans on. Judges who
 * know ML ask about this -- "burst_gap_ratio separated Video from Web" is the
 * kind of answer that lands. Data comes from models/eval_metrics.json via the
 * backend; empty until `python -m core.classifiers.train` has run.
 */
export function FeatureImportance() {
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    modelMetrics()
      .then(setMetrics)
      .catch(() => setFailed(true));
  }, []);

  const importance = metrics?.feature_importance ?? {};
  const rows = Object.entries(importance)
    .map(([feature, value]) => ({ feature, value }))
    .sort((a, b) => b.value - a.value);
  const top = rows.slice(0, 3);

  return (
    <ChartFrame
      title="What the traffic classifier looks at"
      note={
        metrics?.model_version
          ? `RandomForest feature importances · model ${metrics.model_version} · macro-F1 ${
              metrics.f1_macro?.toFixed(2) ?? "—"
            }`
          : "Stage 3 feature importances from the trained Stage 4b model."
      }
      table={
        <table>
          <thead>
            <tr className="text-left text-label-secondary">
              <th className={cellClass}>Feature</th>
              <th className={cellClass}>Importance</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.feature}>
                <td className={cellClass}>{r.feature}</td>
                <td className={`${cellClass} tabular`}>{(r.value * 100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      }
    >
      {failed || rows.length === 0 ? (
        <p className="py-12 text-center text-[length:var(--text-subhead)] text-label-secondary">
          No trained classifier yet &mdash; run <span className="mono">core.classifiers.train</span>.
        </p>
      ) : (
        <>
          <ResponsiveContainer width="100%" height={Math.max(180, rows.length * 24)}>
            <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 24 }}>
              <XAxis type="number" hide domain={[0, "dataMax"]} />
              <YAxis
                type="category"
                dataKey="feature"
                width={148}
                tick={{ fontSize: 11, fill: "var(--label-secondary)" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#2c2c2e",
                  border: "1px solid #38383a",
                  borderRadius: 8,
                  fontSize: 12,
                }}
                formatter={(v) => [`${((v as number) * 100).toFixed(1)}%`, "importance"]}
              />
              <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                {rows.map((r) => (
                  <Cell
                    key={r.feature}
                    fill={top.some((t) => t.feature === r.feature) ? "#4c72b0" : "#48484a"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          {top.length > 0 && (
            <p className="mt-3 text-[length:var(--text-footnote)] text-label-secondary">
              Top discriminators: <span className="mono">{top.map((t) => t.feature).join(", ")}</span>
              .
            </p>
          )}
        </>
      )}
    </ChartFrame>
  );
}
