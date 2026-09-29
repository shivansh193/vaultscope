"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { deleteJob } from "@/lib/api";
import { SEVERITY_HEX } from "@/lib/charts";
import { jobLabel, useJobs } from "@/lib/jobs";
import { SEVERITY_ORDER } from "@/lib/types";

/** Every capture the backend holds, with its verdict at a glance. */
export function RecentCaptures() {
  const router = useRouter();
  const { jobs, select, reload } = useJobs();
  const [deleting, setDeleting] = useState<string>();
  const [error, setError] = useState<string>();

  if (jobs.length === 0) return null;

  async function remove(jobId: string) {
    setDeleting(jobId);
    setError(undefined);
    try {
      await deleteJob(jobId);
      await reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDeleting(undefined);
    }
  }

  return (
    <section className="mt-12 max-w-4xl" aria-label="Analysed captures">
      <h3 className="text-[length:var(--text-headline)] font-semibold tracking-tight">
        Analysed captures
      </h3>
      {error && (
        <p role="alert" className="mt-2 text-[length:var(--text-footnote)] text-critical">
          {error}
        </p>
      )}
      <ul className="mt-3 flex flex-col divide-y divide-separator rounded-xl border border-separator bg-surface">
        {jobs.map((job) => (
          <li
            key={job.job_id}
            data-testid="recent-capture"
            className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3"
          >
            <button
              type="button"
              onClick={() => {
                select(job.job_id);
                router.push("/sessions");
              }}
              className="min-w-0 flex-1 text-left"
            >
              <p className="truncate text-[length:var(--text-subhead)] hover:text-accent">
                {jobLabel(job)}
              </p>
              <p className="text-[length:var(--text-caption)] text-label-tertiary">
                {job.session_count} sessions · {job.stats.packets.toLocaleString()} packets ·
                posture {job.posture_score}
                {job.anomaly_count > 0 && (
                  <span className="text-critical"> · {job.anomaly_count} attack indicators</span>
                )}
              </p>
            </button>
            <span className="flex h-2 w-28 overflow-hidden rounded-full bg-surface-raised" aria-hidden>
              {SEVERITY_ORDER.map((severity) =>
                job.severity_counts[severity] ? (
                  <span
                    key={severity}
                    style={{
                      background: SEVERITY_HEX[severity],
                      flexGrow: job.severity_counts[severity],
                    }}
                  />
                ) : null,
              )}
            </span>
            <button
              type="button"
              aria-label={`Delete ${job.capture_file ?? job.job_id}`}
              disabled={deleting === job.job_id}
              onClick={() => void remove(job.job_id)}
              className="rounded-md px-2 py-1 text-[length:var(--text-caption)] text-label-tertiary hover:bg-surface-raised hover:text-critical disabled:opacity-40"
            >
              Delete
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
