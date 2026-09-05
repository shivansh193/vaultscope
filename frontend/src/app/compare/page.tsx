"use client";

import { useState } from "react";
import { SessionDrilldown } from "@/components/SessionDrilldown";
import { SessionTable } from "@/components/SessionTable";
import { Toolbar } from "@/components/Toolbar";
import { diffJobs } from "@/lib/api";
import { SEVERITY_HEX } from "@/lib/charts";
import { jobHistory } from "@/lib/job";
import type { SessionDiff, VPNSession } from "@/lib/types";

const control =
  "rounded-md border border-separator bg-surface-raised px-2.5 py-1.5 text-[length:var(--text-footnote)] text-label";

export default function ComparePage() {
  const history = typeof window === "undefined" ? [] : jobHistory();
  const [base, setBase] = useState(() => history[1]?.job_id ?? "");
  const [compare, setCompare] = useState(() => history[0]?.job_id ?? "");
  const [result, setResult] = useState<SessionDiff>();
  const [open, setOpen] = useState<VPNSession | null>(null);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(undefined);
    try {
      setResult(await diffJobs(base, compare));
    } catch (e) {
      setError((e as Error).message);
      setResult(undefined);
    } finally {
      setBusy(false);
    }
  }

  const options = history.map((job) => (
    <option key={job.job_id} value={job.job_id}>
      {job.capture_file} · {job.session_count} sessions
    </option>
  ));

  return (
    <div className="flex h-screen flex-col">
      <Toolbar title="Compare" />
      <div className="flex min-h-0 w-full flex-1 overflow-hidden">
        <div className="w-0 flex-1 overflow-y-auto px-7 py-6">
        {history.length < 2 ? (
          <p className="py-24 text-center text-[length:var(--text-subhead)] text-label-secondary">
            Analyse two captures to compare them. One is in; one to go.
          </p>
        ) : (
          <>
            <p className="max-w-[62ch] text-[length:var(--text-footnote)] text-label-secondary">
              Compare a later capture against an earlier one to see which sessions appeared, which
              went away, and which got worse.
            </p>

            <div className="mt-4 flex flex-wrap items-center gap-3 text-[length:var(--text-footnote)] text-label-secondary">
              <label className="flex items-center gap-2">
                Earlier
                <select
                  data-testid="diff-base"
                  value={base}
                  onChange={(e) => setBase(e.target.value)}
                  className={control}
                >
                  {options}
                </select>
              </label>
              <label className="flex items-center gap-2">
                Later
                <select
                  data-testid="diff-compare"
                  value={compare}
                  onChange={(e) => setCompare(e.target.value)}
                  className={control}
                >
                  {options}
                </select>
              </label>
              <button
                type="button"
                data-testid="diff-run"
                disabled={busy || !base || !compare}
                onClick={() => void run()}
                className="rounded-lg bg-accent px-3.5 py-1.5 font-medium text-white hover:bg-[var(--accent-pressed)] disabled:opacity-40"
              >
                {busy ? "Comparing" : "Compare"}
              </button>
            </div>

            {error && (
              <p role="alert" className="mt-6 text-[length:var(--text-subhead)] text-critical">
                Those captures could not be compared. {error}
              </p>
            )}

            {result && (
              <div className="mt-8 flex flex-col gap-8">
                <Section
                  id="added"
                  title="New"
                  note="Sessions the later capture has and the earlier one did not."
                  count={result.added.length}
                >
                  <SessionTable sessions={result.added} onSelect={setOpen} selected={open?.session_id} />
                </Section>

                <Section
                  id="removed"
                  title="Gone"
                  note="Sessions the earlier capture had and the later one does not."
                  count={result.removed.length}
                >
                  <SessionTable sessions={result.removed} onSelect={setOpen} selected={open?.session_id} />
                </Section>

                <Section
                  id="degraded"
                  title="Worse"
                  note="Sessions in both captures whose risk score fell."
                  count={result.degraded.length}
                >
                  <table className="w-full border-collapse text-[length:var(--text-subhead)]">
                    <thead>
                      <tr className="border-b border-separator text-left text-label-secondary">
                        <th className="py-2 pr-4 font-normal">Session</th>
                        <th className="py-2 pr-4 font-normal">Was</th>
                        <th className="py-2 pr-4 font-normal">Now</th>
                        <th className="py-2 pr-4 font-normal">Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.degraded.map((row) => (
                        <tr
                          key={row.session_id}
                          data-testid="degraded-row"
                          onClick={() => setOpen(row.compare)}
                          className="cursor-pointer border-b border-separator/60 hover:brightness-125"
                        >
                          <td className="mono py-2.5 pr-4">{row.session_id}</td>
                          <td className="py-2.5 pr-4" style={{ color: SEVERITY_HEX[row.base_severity] }}>
                            {row.base_severity}
                          </td>
                          <td
                            className="py-2.5 pr-4"
                            style={{ color: SEVERITY_HEX[row.compare_severity] }}
                          >
                            {row.compare_severity}
                          </td>
                          <td className="tabular py-2.5 pr-4">
                            {row.base_score} → {row.compare_score}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Section>
              </div>
            )}
          </>
        )}
        </div>
        {open && <SessionDrilldown session={open} onClose={() => setOpen(null)} />}
      </div>
    </div>
  );
}

function Section({
  id,
  title,
  note,
  count,
  children,
}: {
  id: string;
  title: string;
  note: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <section data-testid={`diff-${id}`}>
      <h2 className="text-[length:var(--text-headline)] font-semibold tracking-tight">
        {title}
        <span className="tabular ml-2 text-label-tertiary">{count}</span>
      </h2>
      <p className="mt-1 text-[length:var(--text-footnote)] text-label-secondary">{note}</p>
      <div className="mt-3 w-full min-w-0 overflow-x-auto">
        {count === 0 ? (
          <p className="py-6 text-[length:var(--text-footnote)] text-label-tertiary">
            Nothing here — which is the good outcome.
          </p>
        ) : (
          children
        )}
      </div>
    </section>
  );
}
