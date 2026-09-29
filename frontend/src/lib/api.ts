/**
 * Typed client for the VaultScope backend (product spec Section 11).
 *
 * Base URL comes from NEXT_PUBLIC_API_BASE so the same static bundle can be
 * served against a local uvicorn, the nginx container, or a hosted backend.
 */

import type {
  AnomalyEvent,
  CaptureInterface,
  Health,
  IngestResult,
  JobSummary,
  LiveStatus,
  ModelMetrics,
  Rule,
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

/** FastAPI errors arrive as {"detail": "..."}; show the sentence, not the JSON. */
function readableDetail(body: string): string {
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
  } catch {
    // not JSON -- fall through to the raw text
  }
  return body;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new ApiError(response.status, readableDetail(detail) || response.statusText);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

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

export const listEvents = (
  params: { job_id?: string; session_id?: string; severity?: string } = {},
) => request<AnomalyEvent[]>(`/events${query(params)}`);

export const listJobs = () => request<JobSummary[]>("/jobs");

export const getJob = (jobId: string) =>
  request<JobSummary>(`/jobs/${encodeURIComponent(jobId)}`);

/**
 * The operator token, when the backend sets VAULTSCOPE_API_TOKEN. Only deleting
 * jobs and interface capture need it; kept per viewer as a convenience.
 */
const TOKEN_KEY = "vaultscope.token";

export function operatorToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setOperatorToken(token: string): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // storage blocked: the token lasts only as long as this call
  }
}

const operatorHeaders = (): Record<string, string> => {
  const token = operatorToken();
  return token ? { "X-VaultScope-Token": token } : {};
};

export const deleteJob = (jobId: string) =>
  request<void>(`/jobs/${encodeURIComponent(jobId)}`, {
    method: "DELETE",
    headers: operatorHeaders(),
  });

/** The capture a job analysed; evidence frame numbers index into this file. */
export const captureUrl = (jobId: string) => `${API_BASE}/jobs/${encodeURIComponent(jobId)}/capture`;

export const listRules = () => request<Rule[]>("/rules");

export const liveStatus = () => request<LiveStatus>("/live/status");

export const liveInterfaces = () => request<CaptureInterface[]>("/live/interfaces");

export const liveStart = (
  body: { source: "replay"; job_id?: string; speed?: number } | { source: "interface"; interface: string },
) => {
  const init = json(body);
  return request<LiveStatus>("/live/start", {
    ...init,
    headers: { ...(init.headers as Record<string, string>), ...operatorHeaders() },
  });
};

export const liveStop = () => request<LiveStatus>("/live/stop", { method: "POST" });

export const diffJobs = (baseJob: string, compareJob: string) =>
  request<SessionDiff>(`/sessions/diff${query({ base_job: baseJob, compare_job: compareJob })}`);

export type ReportType = "executive" | "technical" | "json" | "cef";

export async function requestReport(jobId: string, type: ReportType): Promise<string> {
  const { download_url } = await request<{ download_url: string }>(
    `/report/${encodeURIComponent(jobId)}`,
    json({ type }),
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
export function liveSocketUrl(): string {
  const origin = typeof window === "undefined" ? "http://localhost" : window.location.href;
  const url = new URL(`${API_BASE}/ws/live`, origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}
