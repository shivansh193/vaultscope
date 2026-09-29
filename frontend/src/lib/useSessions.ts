"use client";

import { useCallback, useEffect, useState } from "react";
import { listEvents, listSessions } from "./api";
import { useJobs } from "./jobs";
import type { AnomalyEvent, VPNSession } from "./types";

/**
 * The sessions and anomalies of the capture being looked at.
 *
 * Scoped to the selected job: the database accumulates every capture ever
 * analysed, and a table mixing three captures answers no question anyone asked.
 *
 * Sorting and filtering then happen in the browser: a capture is hundreds of
 * sessions, not millions, and keeping the whole set client-side is what lets
 * the spectrum strip, the peer graph and the table agree on one dataset.
 */
interface Loaded {
  jobId: string;
  sessions: VPNSession[];
  anomalies: AnomalyEvent[];
}

export function useSessions() {
  const { current, loading: jobsLoading, error: jobsError } = useJobs();
  const jobId = current?.job_id;
  const [loaded, setLoaded] = useState<Loaded>();
  const [error, setError] = useState<{ jobId: string; message: string }>();
  const [attempt, setAttempt] = useState(0);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    Promise.all([listSessions({ limit: 1000, job_id: jobId }), listEvents({ job_id: jobId })])
      .then(([sessions, anomalies]) => {
        if (cancelled) return;
        setLoaded({ jobId, sessions, anomalies });
        setError(undefined);
      })
      .catch((e: Error) => !cancelled && setError({ jobId, message: e.message }));
    return () => {
      cancelled = true;
    };
  }, [jobId, attempt]);

  // Everything below is derived, so switching jobs never shows the last job's rows.
  const fresh = loaded && loaded.jobId === jobId ? loaded : undefined;
  const failed = error && error.jobId === jobId ? error.message : undefined;
  return {
    job: current,
    sessions: fresh?.sessions ?? [],
    anomalies: fresh?.anomalies ?? [],
    error: failed ?? jobsError,
    loading: jobsLoading || (Boolean(jobId) && !fresh && !failed),
    reload,
  };
}
