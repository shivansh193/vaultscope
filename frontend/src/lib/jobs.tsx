"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { listJobs } from "./api";
import type { JobSummary } from "./types";

/**
 * The captures the backend has analysed, and which one the console is looking at.
 *
 * Jobs live on the backend, so every tab, reload and teammate sees the same
 * list. Only the *choice* of job is per-viewer, remembered in localStorage as
 * a convenience -- if it is gone or unreadable the newest job is shown.
 */

const KEY = "vaultscope.job";

interface Jobs {
  jobs: JobSummary[];
  current: JobSummary | undefined;
  loading: boolean;
  error: string | undefined;
  select: (jobId: string) => void;
  reload: () => Promise<void>;
}

const JobsContext = createContext<Jobs | null>(null);

function remembered(): string | undefined {
  try {
    return localStorage.getItem(KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

export function JobProvider({ children }: { children: React.ReactNode }) {
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  // Read at first render: nothing depends on it until the job list has loaded,
  // so the static prerender (no storage) and the browser cannot disagree.
  const [selected, setSelected] = useState<string | undefined>(() =>
    typeof window === "undefined" ? undefined : remembered(),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(
    () =>
      listJobs()
        .then((loaded) => {
          setJobs(loaded);
          setError(undefined);
        })
        .catch((e: Error) => setError(e.message))
        .finally(() => setLoading(false)),
    [],
  );

  useEffect(() => {
    void load();
  }, [load]);

  // Awaitable, so a caller that just created a job can select it once it is listed.
  const reload = useCallback(() => load(), [load]);

  const select = useCallback((jobId: string) => {
    setSelected(jobId);
    try {
      localStorage.setItem(KEY, jobId);
    } catch {
      // private window or blocked storage: the choice just is not remembered
    }
  }, []);

  const value = useMemo<Jobs>(
    () => ({
      jobs,
      current: jobs.find((j) => j.job_id === selected) ?? jobs[0],
      loading,
      error,
      select,
      reload,
    }),
    [jobs, selected, loading, error, select, reload],
  );

  return <JobsContext.Provider value={value}>{children}</JobsContext.Provider>;
}

export function useJobs(): Jobs {
  const jobs = useContext(JobsContext);
  if (!jobs) throw new Error("useJobs must be used inside <JobProvider>");
  return jobs;
}

/** "demo.pcap · 29 Sep 14:02" -- how a job is named anywhere a person picks one. */
export function jobLabel(job: JobSummary): string {
  const when = new Date(job.created_at.includes("T") ? job.created_at : `${job.created_at}Z`);
  const stamp = Number.isNaN(when.getTime())
    ? job.created_at
    : when.toLocaleString(undefined, {
        day: "numeric",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      });
  const name = job.source === "live_nic" ? `Live · ${job.capture_file ?? job.job_id}` : job.capture_file;
  return `${name ?? job.job_id} · ${stamp}`;
}
