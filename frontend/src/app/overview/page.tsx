"use client";

import { useRouter } from "next/navigation";
import { AnomalyList } from "@/components/AnomalyList";
import { FeatureImportance } from "@/components/charts/FeatureImportance";
import { RiskHistogram } from "@/components/charts/RiskHistogram";
import { ThreatMatrix } from "@/components/charts/ThreatMatrix";
import { TrafficMix } from "@/components/charts/TrafficMix";
import { JobPicker } from "@/components/JobPicker";
import { Toolbar } from "@/components/Toolbar";
import { SEVERITY_HEX } from "@/lib/charts";
import { useSessions } from "@/lib/useSessions";
import { SEVERITY_ORDER } from "@/lib/types";

export default function OverviewPage() {
  const router = useRouter();
  const { job, sessions, anomalies, loading, error } = useSessions();

  const worstCount = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: sessions.filter((s) => s.security_assessment.overall_severity === severity).length,
  })).filter((entry) => entry.count > 0);

  return (
    <>
      <Toolbar title="Overview">
        <JobPicker />
      </Toolbar>
      <div className="px-4 py-6 md:px-7">
        {job && (
          <p className="text-[length:var(--text-footnote)] text-label-secondary">
            <span className="mono">{job.capture_file}</span> · {sessions.length} sessions ·{" "}
            {job.stats.packets.toLocaleString()} packets over{" "}
            {Math.round(job.stats.duration_sec).toLocaleString()} s
          </p>
        )}
        {!loading && !error && !job && (
          <p className="py-24 text-center text-[length:var(--text-subhead)] text-label-secondary">
            No capture analysed yet. Upload one on the Capture page or start a live run.
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

        {!loading && !error && job && (
          <>
            <ul className="mt-4 flex flex-wrap gap-6">
              <li className="flex items-baseline gap-2" data-testid="posture-score">
                <span className="tabular text-[length:var(--text-title-1)] font-semibold">
                  {job.posture_score}
                </span>
                <span className="text-[length:var(--text-footnote)] text-label-secondary">
                  posture / 100
                </span>
              </li>
              <li className="flex items-baseline gap-2" data-testid="anomaly-count">
                <span
                  className={`tabular text-[length:var(--text-title-1)] font-semibold ${anomalies.length ? "text-critical" : ""}`}
                >
                  {anomalies.length}
                </span>
                <span className="text-[length:var(--text-footnote)] text-label-secondary">
                  attack indicators
                </span>
              </li>
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

            {anomalies.length > 0 && (
              <section className="mt-6 max-w-4xl">
                <h2 className="mb-3 text-[length:var(--text-subhead)] font-semibold">
                  Attack indicators
                </h2>
                <AnomalyList
                  anomalies={anomalies}
                  jobId={job.job_id}
                  captureAvailable={job.capture_available}
                  compact
                  onSelectSession={(id) =>
                    router.push(`/sessions?session=${encodeURIComponent(id)}`)
                  }
                />
              </section>
            )}

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
