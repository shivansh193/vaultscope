/**
 * Typed client for the VaultScope backend (product spec Section 11).
 *
 * Base URL comes from NEXT_PUBLIC_API_BASE so the same static bundle can be
 * served against a local uvicorn, the nginx container, or the mock server.
 */

import type {
  AnomalyEvent,
  Health,
  IngestResult,
  ModelMetrics,
  SessionDiff,
  Severity,
  VPNSession,
} from "./types";

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000").replace(
  /\/$/,
  "",
);

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new ApiError(response.status, detail || response.statusText);
  }
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

export const health = () => request<Health>("/health");

export const modelMetrics = () => request<ModelMetrics>("/model/metrics");

export function ingest(file: File): Promise<IngestResult> {
  const body = new FormData();
  body.append("file", file);
  return request<IngestResult>("/ingest", { method: "POST", body });
}

export const listSessions = (
  params: { severity?: Severity; job_id?: string; limit?: number; offset?: number } = {},
) =>
  request<VPNSession[]>(`/sessions${query(params)}`);

export const getSession = (sessionId: string) =>
  request<VPNSession>(`/session/${encodeURIComponent(sessionId)}`);

export const listEvents = (params: { session_id?: string; severity?: string } = {}) =>
  request<AnomalyEvent[]>(`/events${query(params)}`);

export const diffJobs = (baseJob: string, compareJob: string) =>
  request<SessionDiff>(`/sessions/diff${query({ base_job: baseJob, compare_job: compareJob })}`);

export type ReportType = "executive" | "technical" | "json" | "cef";

export async function requestReport(jobId: string, type: ReportType): Promise<string> {
  const { download_url } = await request<{ download_url: string }>(
    `/report/${encodeURIComponent(jobId)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type }),
    },
  );
  return download_url.startsWith("http") ? download_url : `${API_BASE}${download_url}`;
}

/**
 * WebSocket URL for /ws/live, derived from the HTTP base.
 *
 * The base is absolute in development and relative ("/api") behind nginx,
 * where the console is served same-origin -- so resolve against the page
 * before switching the scheme.
 */
export function liveSocketUrl(nic?: string): string {
  const origin = typeof window === "undefined" ? "http://localhost" : window.location.href;
  const url = new URL(`${API_BASE}/ws/live`, origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (nic) url.searchParams.set("nic", nic);
  return url.toString();
}
