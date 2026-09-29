import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RecentCaptures } from "./RecentCaptures";
import type { JobSummary } from "@/lib/types";

const job: JobSummary = {
  job_id: "j1",
  capture_file: "demo.pcap",
  source: "pcap_upload",
  created_at: "2026-09-29T10:00:00Z",
  stats: {
    packets: 10,
    ike_packets: 10,
    esp_packets: 0,
    duration_sec: 1,
    sessions: 1,
    incomplete_sessions: 0,
    orphan_esp_packets: 0,
  },
  session_count: 1,
  severity_counts: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 },
  posture_score: 20,
  anomaly_count: 0,
  capture_available: true,
};

const reload = vi.fn(async () => undefined);
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/lib/jobs", () => ({
  useJobs: () => ({ jobs: [job], select: vi.fn(), reload }),
  jobLabel: () => "demo.pcap",
}));

afterEach(() => vi.unstubAllGlobals());

describe("RecentCaptures", () => {
  it("asks once more before deleting a capture for good", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal("fetch", fetchMock);
    render(<RecentCaptures />);

    await userEvent.click(screen.getByRole("button", { name: "Delete demo.pcap" }));
    expect(fetchMock).not.toHaveBeenCalled();
    await userEvent.click(screen.getByTestId("confirm-delete"));
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: "DELETE" });
  });

  it("asks for the operator token when the backend requires one", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => JSON.stringify({ detail: "operator token required" }),
      }),
    );
    render(<RecentCaptures />);
    await userEvent.click(screen.getByRole("button", { name: "Delete demo.pcap" }));
    await userEvent.click(screen.getByTestId("confirm-delete"));
    expect(await screen.findByTestId("operator-token")).toBeInTheDocument();
  });
});
