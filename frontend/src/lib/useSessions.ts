"use client";

import { useCallback, useEffect, useState } from "react";
import { listSessions } from "./api";
import { currentJob } from "./job";
import type { VPNSession } from "./types";

/**
 * The sessions of the capture being looked at.
 *
 * Scoped to the most recent ingest: the database accumulates every capture ever
 * uploaded, and a table mixing three captures answers no question anyone asked.
 * Pass `allCaptures` to read across every job -- the compare view does.
 *
 * Sorting and filtering then happen in the browser: a capture is hundreds of
 * sessions, not millions, and keeping the whole set client-side is what lets
 * the spectrum strip, the peer graph and the table agree on one dataset.
 */
export function useSessions({ allCaptures = false }: { allCaptures?: boolean } = {}) {
  const [sessions, setSessions] = useState<VPNSession[]>([]);
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    listSessions({ limit: 1000, job_id: allCaptures ? undefined : currentJob()?.job_id })
      .then((loaded) => {
        if (cancelled) return;
        setSessions(loaded);
        setError(undefined);
      })
      .catch((e: Error) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [allCaptures, attempt]);

  return { sessions, setSessions, error, loading, reload };
}
