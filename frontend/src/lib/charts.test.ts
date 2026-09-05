import { describe, expect, it } from "vitest";
import {
  peerGraph,
  rampStep,
  riskHistogram,
  threatMatrix,
  trafficMix,
  TRAFFIC_ORDER,
} from "./charts";
import { session } from "@/test/factory";
import type { VPNSession } from "./types";

const withTraffic = (id: string, type: VPNSession["traffic_prediction"]["predicted_type"]) => {
  const s = session(id);
  s.traffic_prediction.predicted_type = type;
  return s;
};

describe("riskHistogram", () => {
  it("bins every score into ten bands, including the endpoints", () => {
    const bins = riskHistogram([
      session("a", { score: 0 }),
      session("b", { score: 100 }),
      session("c", { score: 55 }),
    ]);
    expect(bins).toHaveLength(10);
    expect(bins[0].count).toBe(1);
    expect(bins[5].count).toBe(1);
    expect(bins[9].count).toBe(1); // 100 belongs in the top band, not an eleventh
  });

  it("keeps empty bands so the axis does not shift between captures", () => {
    expect(riskHistogram([]).every((b) => b.count === 0)).toBe(true);
    expect(riskHistogram([])).toHaveLength(10);
  });
});

describe("trafficMix", () => {
  it("counts each predicted type once", () => {
    const mix = trafficMix([withTraffic("a", "VoIP"), withTraffic("b", "VoIP"), withTraffic("c", "Web")]);
    expect(mix).toEqual([
      { type: "VoIP", count: 2 },
      { type: "Web", count: 1 },
    ]);
  });

  it("keeps the fixed slot order so a hue never moves between captures", () => {
    const mix = trafficMix([withTraffic("a", "Other"), withTraffic("b", "VoIP")]);
    expect(mix.map((m) => m.type)).toEqual(["VoIP", "Other"]);
    expect(TRAFFIC_ORDER.indexOf("VoIP")).toBeLessThan(TRAFFIC_ORDER.indexOf("Other"));
  });
});

describe("threatMatrix", () => {
  it("always returns the full 3x3 grid", () => {
    expect(threatMatrix([])).toHaveLength(9);
  });

  it("counts threats into their cell and lists each threat once", () => {
    const a = session("a");
    a.security_assessment.threat_matrix = [
      { threat: "Offline PSK cracking", likelihood: "High", impact: "High" },
      { threat: "Offline PSK cracking", likelihood: "High", impact: "High" },
    ];
    const cell = threatMatrix([a]).find((c) => c.likelihood === "High" && c.impact === "High")!;
    expect(cell.count).toBe(2);
    expect(cell.threats).toEqual(["Offline PSK cracking"]);
  });
});

describe("rampStep", () => {
  it("leaves empty cells on the surface colour rather than the palest step", () => {
    expect(rampStep(0, 10)).toBe("var(--surface-raised)");
  });

  it("darkens with the count", () => {
    expect(rampStep(10, 10)).toBe("var(--ramp-1)");
    expect(rampStep(1, 10)).toBe("var(--ramp-5)");
  });
});

describe("peerGraph", () => {
  const capture = [
    session("s1", { severity: "LOW", initiator: "10.0.0.1", responder: "10.0.0.2" }),
    session("s2", { severity: "CRITICAL", initiator: "10.0.0.1", responder: "10.0.0.3" }),
  ];

  it("makes one node per unique peer", () => {
    expect(peerGraph(capture).nodes.map((n) => n.id)).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
  });

  it("colours a peer by its worst session, not its latest", () => {
    const shared = peerGraph(capture).nodes.find((n) => n.id === "10.0.0.1")!;
    expect(shared.severity).toBe("CRITICAL");
    expect(shared.sessions).toBe(2);
  });

  it("makes one edge per session, carrying the session id", () => {
    expect(peerGraph(capture).edges.map((e) => e.sessionId)).toEqual(["s1", "s2"]);
  });

  it("skips sessions with no peer addresses rather than inventing a node", () => {
    expect(peerGraph([session("x", { initiator: "", responder: "" })]).nodes).toEqual([]);
  });
});
