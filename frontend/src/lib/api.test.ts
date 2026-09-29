import { afterEach, describe, expect, it, vi } from "vitest";
import {
  API_BASE,
  ApiError,
  captureUrl,
  deleteJob,
  ingest,
  listJobs,
  listSessions,
  liveSocketUrl,
  liveStart,
} from "./api";

afterEach(() => vi.unstubAllGlobals());

function stubFetch(response: Partial<Response>) {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => [], ...response });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("api client", () => {
  it("omits empty query parameters instead of sending severity=undefined", async () => {
    const fetchMock = stubFetch({});
    await listSessions({ limit: 50 });
    expect(fetchMock).toHaveBeenCalledWith(`${API_BASE}/sessions?limit=50`, undefined);
  });

  it("sends the capture as multipart form data", async () => {
    const fetchMock = stubFetch({ json: async () => ({ job_id: "j1", session_count: 1 }) });
    await ingest(new File(["pcap"], "capture.pcap"));
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect((init.body as FormData).get("file")).toBeInstanceOf(File);
  });

  it("raises ApiError carrying the status so callers can tell 404 from 500", async () => {
    stubFetch({ ok: false, status: 404, text: async () => "session not found" });
    await expect(listSessions()).rejects.toMatchObject({
      name: "ApiError",
      status: 404,
      message: "session not found",
    });
    expect(new ApiError(500, "x")).toBeInstanceOf(Error);
  });

  it("derives the websocket URL from the http base", () => {
    expect(liveSocketUrl()).toBe(`${API_BASE.replace(/^http/, "ws")}/ws/live`);
  });

  it("surfaces FastAPI's detail sentence rather than the raw JSON body", async () => {
    stubFetch({
      ok: false,
      status: 415,
      text: async () => JSON.stringify({ detail: "not a pcap or pcapng capture" }),
    });
    await expect(listJobs()).rejects.toMatchObject({
      status: 415,
      message: "not a pcap or pcapng capture",
    });
  });

  it("treats 204 No Content as success with no body", async () => {
    const fetchMock = stubFetch({ status: 204, json: async () => Promise.reject(new Error("no body")) });
    await expect(deleteJob("j1")).resolves.toBeUndefined();
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: "DELETE" });
  });

  it("starts a replay run with a JSON body", async () => {
    const fetchMock = stubFetch({ json: async () => ({ state: "running" }) });
    await liveStart({ source: "replay", speed: 50 });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${API_BASE}/live/start`);
    expect(JSON.parse(init.body as string)).toEqual({ source: "replay", speed: 50 });
  });

  it("builds a capture download link per job", () => {
    expect(captureUrl("a b")).toBe(`${API_BASE}/jobs/a%20b/capture`);
  });
});

describe("liveSocketUrl behind a relative base", () => {
  it("resolves against the page when the API base is a path", async () => {
    vi.resetModules();
    vi.stubEnv("NEXT_PUBLIC_API_BASE", "/api");
    const { liveSocketUrl: relative } = await import("./api");
    expect(relative()).toBe(`ws://${window.location.host}/api/ws/live`);
    vi.unstubAllEnvs();
  });
});
