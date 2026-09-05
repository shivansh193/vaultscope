"use client";

import { useMemo, useState } from "react";
import { CaptureSpectrum } from "@/components/CaptureSpectrum";
import { SessionDrilldown } from "@/components/SessionDrilldown";
import { SessionTable } from "@/components/SessionTable";
import { Toolbar } from "@/components/Toolbar";
import { currentJob } from "@/lib/job";
import {
  filterSessions,
  page as pageOf,
  pageCount,
  sortSessions,
  type Filters,
  type SortDirection,
  type SortKey,
} from "@/lib/sessions";
import { useSessions } from "@/lib/useSessions";
import type { Severity, VPNSession } from "@/lib/types";

const PER_PAGE = 25;
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];

const control =
  "rounded-md border border-separator bg-surface-raised px-2.5 py-1.5 text-[length:var(--text-footnote)] text-label";

export default function SessionsPage() {
  const { sessions, loading, error } = useSessions();
  // The peer graph links here with ?peer=<ip> to narrow the table to one peer.
  const [filters, setFilters] = useState<Filters>(() => {
    if (typeof window === "undefined") return {};
    const peer = new URLSearchParams(window.location.search).get("peer");
    return peer ? { peer } : {};
  });
  const [sort, setSort] = useState<SortKey>("risk");
  const [direction, setDirection] = useState<SortDirection>("asc");
  const [pageIndex, setPageIndex] = useState(0);
  const [sortTouched, setSortTouched] = useState(false);
  const [selected, setSelected] = useState<VPNSession>();
  const job = typeof window === "undefined" ? undefined : currentJob();

  const visible = useMemo(
    () => sortSessions(filterSessions(sessions, filters), sort, direction),
    [sessions, filters, sort, direction],
  );
  const pages = pageCount(visible.length, PER_PAGE);
  const current = Math.min(pageIndex, pages - 1);
  const rows = pageOf(visible, current, PER_PAGE);

  function toggleSort(key: SortKey) {
    // The table opens sorted worst-first because that is the question a capture
    // is opened to answer. Clicking that column the first time re-asserts the
    // order rather than reversing it -- reversing on the very first click would
    // hide what the user came to see. After that it toggles normally.
    if (key === sort && !sortTouched) setDirection("asc");
    else if (key === sort) setDirection(direction === "asc" ? "desc" : "asc");
    else {
      setSort(key);
      setDirection("asc");
    }
    setSortTouched(true);
    setPageIndex(0);
  }

  function update(patch: Filters) {
    setFilters((f) => ({ ...f, ...patch }));
    setPageIndex(0);
  }

  return (
    <div className="flex h-screen flex-col">
      <Toolbar title="Sessions">
        <input
          type="search"
          data-testid="filter-search"
          placeholder="Peer, cipher, vendor"
          value={filters.search ?? ""}
          onChange={(e) => update({ search: e.target.value })}
          className={`${control} w-56 placeholder:text-label-tertiary`}
        />
        <select
          data-testid="filter-ike-version"
          aria-label="IKE version"
          value={filters.ikeVersion ?? ""}
          onChange={(e) => update({ ikeVersion: (e.target.value || undefined) as Filters["ikeVersion"] })}
          className={control}
        >
          <option value="">Any IKE version</option>
          <option value="IKEv1">IKEv1</option>
          <option value="IKEv2">IKEv2</option>
        </select>
        <select
          data-testid="filter-severity"
          aria-label="Severity"
          value={filters.severity ?? ""}
          onChange={(e) => update({ severity: (e.target.value || undefined) as Severity })}
          className={control}
        >
          <option value="">Any severity</option>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </Toolbar>

      <div className="flex min-h-0 w-full flex-1 overflow-hidden">
        <div className="w-0 flex-1 overflow-y-auto px-7 py-6">
          {job && (
            <p className="mb-4 text-[length:var(--text-footnote)] text-label-secondary">
              <span className="mono">{job.capture_file}</span> · {job.session_count} sessions
              {job.fixture_mode && " · fixture data, not a real decode"}
            </p>
          )}

          <CaptureSpectrum
            sessions={sessions}
            selected={selected?.session_id}
            onSelect={(id) => setSelected(sessions.find((s) => s.session_id === id))}
          />

          {filters.peer && (
            <button
              type="button"
              onClick={() => update({ peer: undefined })}
              className="mt-4 rounded-md bg-surface-raised px-2.5 py-1 text-[length:var(--text-footnote)] text-label-secondary hover:text-label"
            >
              Peer <span className="mono">{filters.peer}</span> ✕
            </button>
          )}

          <div className="mt-5 w-full min-w-0 overflow-x-auto">
            {loading && (
              <p className="py-16 text-center text-[length:var(--text-subhead)] text-label-secondary">
                Loading sessions
              </p>
            )}
            {error && (
              <p role="alert" className="py-16 text-center text-[length:var(--text-subhead)] text-critical">
                Sessions could not be loaded. {error}
              </p>
            )}
            {!loading && !error && (
              <SessionTable
                sessions={rows}
                sort={sort}
                direction={direction}
                onSort={toggleSort}
                onSelect={setSelected}
                selected={selected?.session_id}
              />
            )}
          </div>

          {pages > 1 && (
            <div className="mt-5 flex items-center gap-3 text-[length:var(--text-footnote)]">
              <button
                type="button"
                data-testid="page-prev"
                disabled={current === 0}
                onClick={() => setPageIndex(current - 1)}
                className={`${control} disabled:opacity-35`}
              >
                Previous
              </button>
              <span className="tabular text-label-secondary">
                Page {current + 1} of {pages} · {visible.length} sessions
              </span>
              <button
                type="button"
                data-testid="page-next"
                disabled={current >= pages - 1}
                onClick={() => setPageIndex(current + 1)}
                className={`${control} disabled:opacity-35`}
              >
                Next
              </button>
            </div>
          )}
        </div>

        {selected && (
          <SessionDrilldown session={selected} onClose={() => setSelected(undefined)} />
        )}
      </div>
    </div>
  );
}
