"use client";

import { useState } from "react";
import { Toolbar } from "@/components/Toolbar";
import { requestReport, type ReportType } from "@/lib/api";
import { currentJob, jobHistory } from "@/lib/job";

const REPORTS: { type: ReportType; title: string; note: string }[] = [
  {
    type: "executive",
    title: "Executive report",
    note: "One or two pages of PDF: the score, the worst findings, what to do about them.",
  },
  {
    type: "technical",
    title: "Technical report",
    note: "Every session, every finding with its standard and CVE, and the vendor config diffs.",
  },
  {
    type: "json",
    title: "JSON export",
    note: "The canonical session records, exactly as the pipeline persisted them.",
  },
  {
    type: "cef",
    title: "CEF export",
    note: "Common Event Format, one line per finding, for a SIEM to ingest.",
  },
];

type Status = Record<string, { state: "building" | "ready" | "failed"; detail: string }>;

export default function ExportPage() {
  const [jobId, setJobId] = useState(() => (typeof window === "undefined" ? "" : currentJob()?.job_id ?? ""));
  const history = typeof window === "undefined" ? [] : jobHistory();
  const [status, setStatus] = useState<Status>({});

  async function build(type: ReportType) {
    setStatus((s) => ({ ...s, [type]: { state: "building", detail: "" } }));
    try {
      const url = await requestReport(jobId, type);
      setStatus((s) => ({ ...s, [type]: { state: "ready", detail: url } }));
      window.open(url, "_blank", "noopener");
    } catch (error) {
      setStatus((s) => ({ ...s, [type]: { state: "failed", detail: (error as Error).message } }));
    }
  }

  return (
    <>
      <Toolbar title="Export" />
      <div className="px-7 py-6">
        {history.length === 0 ? (
          <p className="py-24 text-center text-[length:var(--text-subhead)] text-label-secondary">
            Nothing to export yet. Analyse a capture first.
          </p>
        ) : (
          <>
            <label className="flex flex-wrap items-center gap-3 text-[length:var(--text-footnote)] text-label-secondary">
              Capture
              <select
                data-testid="export-job"
                value={jobId}
                onChange={(e) => setJobId(e.target.value)}
                className="rounded-md border border-separator bg-surface-raised px-2.5 py-1.5 text-label"
              >
                {history.map((job) => (
                  <option key={job.job_id} value={job.job_id}>
                    {job.capture_file} · {job.session_count} sessions
                  </option>
                ))}
              </select>
            </label>

            <ul className="mt-6 grid max-w-4xl gap-4 md:grid-cols-2">
              {REPORTS.map(({ type, title, note }) => {
                const current = status[type];
                return (
                  <li
                    key={type}
                    className="flex flex-col rounded-xl border border-separator bg-surface p-5"
                  >
                    <h3 className="text-[length:var(--text-headline)] font-semibold tracking-tight">
                      {title}
                    </h3>
                    <p className="mt-1 text-[length:var(--text-footnote)] text-label-secondary">
                      {note}
                    </p>
                    <button
                      type="button"
                      data-testid={`export-${type}`}
                      disabled={current?.state === "building"}
                      onClick={() => void build(type)}
                      className="mt-4 self-start rounded-lg bg-accent px-3.5 py-1.5 text-[length:var(--text-footnote)] font-medium text-white hover:bg-[var(--accent-pressed)] disabled:opacity-40"
                    >
                      {current?.state === "building" ? "Building" : "Build and download"}
                    </button>
                    {current?.state === "ready" && (
                      <a
                        data-testid={`download-${type}`}
                        href={current.detail}
                        target="_blank"
                        rel="noopener"
                        className="mt-2 text-[length:var(--text-caption)] text-accent hover:underline"
                      >
                        Download again
                      </a>
                    )}
                    {current?.state === "failed" && (
                      <p role="alert" className="mt-2 text-[length:var(--text-caption)] text-critical">
                        {title} could not be built. {current.detail}
                      </p>
                    )}
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </div>
    </>
  );
}
