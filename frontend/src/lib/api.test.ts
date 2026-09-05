import { afterEach, describe, expect, it, vi } from "vitest";
import { API_BASE, ApiError, ingest, listSessions, liveSocketUrl } from "./api";

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
    expect(liveSocketUrl("eth0")).toBe(
      `${API_BASE.replace(/^http/, "ws")}/ws/live?nic=eth0`,
    );
  });
});
