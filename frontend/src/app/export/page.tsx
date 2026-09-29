"use client";

import { useState } from "react";
import { Toolbar } from "@/components/Toolbar";
import { JobPicker } from "@/components/JobPicker";
import { captureUrl, requestReport, type ReportType } from "@/lib/api";
import { useJobs } from "@/lib/jobs";

const REPORTS: { type: ReportType; title: string; note: string }[] = [
  {
    type: "executive",
    title: "Executive report",
    note: "One or two pages of PDF: the score, the worst findings, what to do about them.",
  },
  {
    type: "technical",
    title: "Technical report",
    note: "Every session, every finding with its standard and CVE, runtime anomalies with their evidence frames, and the vendor config diffs.",
  },
  {
    type: "json",
    title: "JSON export",
    note: "The canonical session records, each carrying the anomalies raised against it.",
  },
  {
    type: "cef",
    title: "CEF export",
    note: "Common Event Format for a SIEM: one event per finding, one per anomaly.",
  },
];

type Status = Record<string, { state: "building" | "ready" | "failed"; detail: string }>;

export default function ExportPage() {
  const { current, jobs } = useJobs();
  const jobId = current?.job_id ?? "";
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
      <Toolbar title="Export">
        <JobPicker />
      </Toolbar>
      <div className="px-4 py-6 md:px-7">
        {jobs.length === 0 ? (
          <p className="py-24 text-center text-[length:var(--text-subhead)] text-label-secondary">
            Nothing to export yet. Analyse a capture first.
          </p>
        ) : (
          <>
            <p className="text-[length:var(--text-footnote)] text-label-secondary">
              Reports cover the capture selected above:{" "}
              <span className="mono">{current?.capture_file}</span> · {current?.session_count}{" "}
              sessions · {current?.anomaly_count} anomalies.
            </p>

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
              {current?.capture_available && (
                <li className="flex flex-col rounded-xl border border-separator bg-surface p-5">
                  <h3 className="text-[length:var(--text-headline)] font-semibold tracking-tight">
                    Original capture
                  </h3>
                  <p className="mt-1 text-[length:var(--text-footnote)] text-label-secondary">
                    The exact pcap this job analysed. Every evidence frame number in the reports
                    indexes into this file — open it in Wireshark to verify.
                  </p>
                  <a
                    data-testid="export-capture"
                    href={captureUrl(jobId)}
                    className="mt-4 self-start rounded-lg border border-separator bg-surface-raised px-3.5 py-1.5 text-[length:var(--text-footnote)] font-medium text-label hover:bg-surface-control"
                  >
                    Download capture
                  </a>
                </li>
              )}
            </ul>
          </>
        )}
      </div>
    </>
  );
}
