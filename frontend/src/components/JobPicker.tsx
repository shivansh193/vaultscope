"use client";

import { jobLabel, useJobs } from "@/lib/jobs";

/** Which capture every view is looking at. Lives in the toolbar of each job-scoped view. */
export function JobPicker() {
  const { jobs, current, select } = useJobs();
  if (jobs.length === 0) return null;

  return (
    <select
      data-testid="job-picker"
      aria-label="Capture"
      value={current?.job_id ?? ""}
      onChange={(e) => select(e.target.value)}
      className="max-w-[16rem] truncate rounded-md border border-separator bg-surface-raised px-2.5 py-1.5 text-[length:var(--text-footnote)] text-label"
    >
      {jobs.map((job) => (
        <option key={job.job_id} value={job.job_id}>
          {jobLabel(job)} · {job.session_count} sessions
        </option>
      ))}
    </select>
  );
}
