import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AnomalyList, anomalyTitle } from "./AnomalyList";
import { SessionDrilldown } from "./SessionDrilldown";
import { SessionTable } from "./SessionTable";
import { API_BASE } from "@/lib/api";
import { jobLabel } from "@/lib/jobs";
import { session } from "@/test/factory";
import type { AnomalyEvent, JobSummary } from "@/lib/types";

const probe: AnomalyEvent = {
  anomaly_id: "a1",
  session_id: "s-bad",
  timestamp: "2026-09-05T18:41:32.808246+00:00",
  anomaly_type: "AGGRESSIVE_MODE_PROBE",
  severity: "HIGH",
  description: "IKEv1 Aggressive Mode exchange to 192.168.20.1 exposes the PSK hash",
  evidence_pkts: [9, 10],
};

describe("AnomalyList", () => {
  it("names the frames that prove each anomaly", () => {
    render(<AnomalyList anomalies={[probe]} />);
    expect(screen.getByText("Aggressive mode probe")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-frames")).toHaveTextContent("frames 9, 10");
  });

  it("links the exact capture so the frames can be checked in Wireshark", () => {
    render(<AnomalyList anomalies={[probe]} jobId="job-1" captureAvailable />);
    expect(screen.getByTestId("download-capture")).toHaveAttribute(
      "href",
      `${API_BASE}/jobs/job-1/capture`,
    );
  });

  it("offers no download when the capture was not retained", () => {
    render(<AnomalyList anomalies={[probe]} jobId="job-1" captureAvailable={false} />);
    expect(screen.queryByTestId("download-capture")).toBeNull();
  });

  it("opens the session an anomaly was raised against", async () => {
    const onSelect = vi.fn();
    render(<AnomalyList anomalies={[probe]} onSelectSession={onSelect} />);
    await userEvent.click(screen.getByRole("button", { name: "open session" }));
    expect(onSelect).toHaveBeenCalledWith("s-bad");
  });

  it("renders nothing when there is nothing to report", () => {
    const { container } = render(<AnomalyList anomalies={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("folds one detector's events into one card with every frame", () => {
    const second = { ...probe, anomaly_id: "a2", session_id: "s-2", evidence_pkts: [3, 4] };
    render(<AnomalyList anomalies={[probe, second]} onSelectSession={vi.fn()} />);
    expect(screen.getAllByTestId("anomaly")).toHaveLength(1);
    expect(screen.getByTestId("evidence-frames")).toHaveTextContent("frames 3, 4, 9, 10");
    expect(screen.getByText("2 sessions")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /session \d/ })).toHaveLength(2);
  });

  it("titles anomaly types in sentence case", () => {
    expect(anomalyTitle("DOWNGRADE_SUSPECTED")).toBe("Downgrade suspected");
    expect(anomalyTitle("NAT_T_UNEXPECTED")).toBe("NAT-T unexpected");
    expect(anomalyTitle("SPI_COLLISION")).toBe("SPI collision");
  });
});

describe("honest session display", () => {
  it("flags sessions with runtime anomalies in the table", () => {
    render(
      <SessionTable
        sessions={[session("s-bad", { severity: "CRITICAL" }), session("s-ok")]}
        onSelect={vi.fn()}
        flagged={new Set(["s-bad"])}
      />,
    );
    const bad = screen.getByText("MODP1024").closest("tr")!;
    expect(within(bad).getByTestId("anomaly-flag")).toBeInTheDocument();
    expect(screen.getAllByTestId("anomaly-flag")).toHaveLength(1);
  });

  it("says 'no ESP' rather than a traffic guess when there was nothing to measure", () => {
    const quiet = session("s-quiet");
    quiet.traffic_prediction = {
      ...quiet.traffic_prediction,
      predicted_type: "Other",
      confidence: 0,
      model_version: "no-esp-observed",
    };
    render(<SessionTable sessions={[quiet]} onSelect={vi.fn()} />);
    expect(screen.getByText("no ESP")).toBeInTheDocument();
    expect(screen.queryByText("Other")).toBeNull();
  });

  it("marks classifier-inferred crypto and lists evidence frames in the drilldown", () => {
    const partial = session("s-partial");
    partial.ike.confidence_source = "classifier";
    partial.ike.inferred_fields = ["encryption"];
    partial.ike.encryption = "AES-128-CBC";
    partial.packet_refs = [3, 4];
    render(<SessionDrilldown session={partial} onClose={vi.fn()} anomalies={[probe]} />);
    expect(screen.getByText("AES-128-CBC (inferred)")).toBeInTheDocument();
    expect(screen.getByText("ECP256")).toBeInTheDocument(); // parsed, so unmarked
    expect(screen.getByText("3, 4")).toBeInTheDocument();
    expect(screen.getByTestId("session-anomalies")).toHaveTextContent("Aggressive mode probe");
  });
});

describe("jobLabel", () => {
  const job = (overrides: Partial<JobSummary>): JobSummary => ({
    job_id: "j1",
    capture_file: "demo.pcap",
    source: "pcap_upload",
    created_at: "2026-09-29T10:00:00Z",
    stats: {
      packets: 0,
      ike_packets: 0,
      esp_packets: 0,
      duration_sec: 0,
      sessions: 0,
      incomplete_sessions: 0,
      orphan_esp_packets: 0,
    },
    session_count: 0,
    severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 },
    posture_score: 100,
    anomaly_count: 0,
    capture_available: true,
    ...overrides,
  });

  it("names uploads by file and live runs as live", () => {
    expect(jobLabel(job({}))).toMatch(/^demo\.pcap · /);
    expect(jobLabel(job({ source: "live_nic", capture_file: "live-abc.pcap" }))).toMatch(
      /^Live · live-abc\.pcap · /,
    );
  });

  it("reads SQLite's space-separated timestamps as UTC", () => {
    expect(jobLabel(job({ created_at: "2026-09-29 10:00:00" }))).not.toContain("Invalid");
  });
});

describe("nothing unobserved is shown as observed", () => {
  it("says 'not observed' for lifetime and anti-replay the capture never showed", () => {
    const s = session("s-quiet");
    s.ike.sa_lifetime_sec = null;
    s.ike.anti_replay = null;
    render(<SessionDrilldown session={s} onClose={vi.fn()} />);
    expect(screen.getAllByText("not observed")).toHaveLength(2);
  });

  it("flags a finding that rests on an inferred value", () => {
    const s = session("s-bad", { severity: "CRITICAL" });
    s.security_assessment.findings[0].inferred_from = ["dh_group"];
    render(<SessionDrilldown session={s} onClose={vi.fn()} />);
    expect(screen.getByTestId("finding-inferred")).toHaveTextContent("inferred dh group");
  });
});
