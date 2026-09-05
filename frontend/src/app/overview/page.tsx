"use client";

import { FeatureImportance } from "@/components/charts/FeatureImportance";
import { RiskHistogram } from "@/components/charts/RiskHistogram";
import { ThreatMatrix } from "@/components/charts/ThreatMatrix";
import { TrafficMix } from "@/components/charts/TrafficMix";
import { Toolbar } from "@/components/Toolbar";
import { SEVERITY_HEX } from "@/lib/charts";
import { currentJob } from "@/lib/job";
import { useSessions } from "@/lib/useSessions";
import { SEVERITY_ORDER } from "@/lib/types";

export default function OverviewPage() {
  const { sessions, loading, error } = useSessions();
  const job = typeof window === "undefined" ? undefined : currentJob();

  const worstCount = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: sessions.filter((s) => s.security_assessment.overall_severity === severity).length,
  })).filter((entry) => entry.count > 0);

  return (
    <>
      <Toolbar title="Overview" />
      <div className="px-7 py-6">
        {job && (
          <p className="text-[length:var(--text-footnote)] text-label-secondary">
            <span className="mono">{job.capture_file}</span> · {sessions.length} sessions
          </p>
        )}

        {loading && (
          <p className="py-24 text-center text-[length:var(--text-subhead)] text-label-secondary">
            Loading the capture
          </p>
        )}
        {error && (
          <p role="alert" className="py-24 text-center text-[length:var(--text-subhead)] text-critical">
            The capture could not be loaded. {error}
          </p>
        )}

        {!loading && !error && (
          <>
            <ul className="mt-4 flex flex-wrap gap-6">
              {worstCount.map(({ severity, count }) => (
                <li key={severity} className="flex items-baseline gap-2">
                  <span
                    aria-hidden
                    className="h-2.5 w-2.5 self-center rounded-full"
                    style={{ background: SEVERITY_HEX[severity] }}
                  />
                  <span className="tabular text-[length:var(--text-title-1)] font-semibold">
                    {count}
                  </span>
                  <span className="text-[length:var(--text-footnote)] text-label-secondary">
                    {severity.toLowerCase()}
                  </span>
                </li>
              ))}
            </ul>

            <div className="mt-6 grid gap-5 xl:grid-cols-2">
              <RiskHistogram sessions={sessions} />
              <TrafficMix sessions={sessions} />
              <ThreatMatrix sessions={sessions} />
              <FeatureImportance />
            </div>
          </>
        )}
      </div>
    </>
  );
}
