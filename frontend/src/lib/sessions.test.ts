import { describe, expect, it } from "vitest";
import { filterSessions, page, pageCount, peers, sortSessions } from "./sessions";
import type { Severity, VPNSession } from "./types";
import { session } from "../test/factory";

const capture: VPNSession[] = [
  session("s-web", { severity: "LOW", score: 80, encryption: "AES-256-GCM", initiator: "10.0.0.9" }),
  session("s-old", {
    severity: "CRITICAL",
    score: 20,
    encryption: "3DES-CBC",
    version: "IKEv1",
    initiator: "10.0.0.10",
  }),
  session("s-mid", { severity: "HIGH", score: 55, encryption: "AES-128-CBC", initiator: "10.0.0.2" }),
];

describe("sortSessions", () => {
  it("puts the worst severity first when sorting by risk", () => {
    const order = sortSessions(capture, "risk").map((s) => s.session_id);
    expect(order).toEqual(["s-old", "s-mid", "s-web"]);
  });

  it("reverses on descending without mutating the input", () => {
    const before = capture.map((s) => s.session_id);
    expect(sortSessions(capture, "risk", "desc")[0].session_id).toBe("s-web");
    expect(capture.map((s) => s.session_id)).toEqual(before);
  });

  it("orders IPv4 peers numerically, so .9 comes before .10", () => {
    expect(sortSessions(capture, "peer").map((s) => s.initiator_ip)).toEqual([
      "10.0.0.2",
      "10.0.0.9",
      "10.0.0.10",
    ]);
  });

  it("sorts by cipher name", () => {
    expect(sortSessions(capture, "cipher").map((s) => s.ike.encryption)).toEqual([
      "3DES-CBC",
      "AES-128-CBC",
      "AES-256-GCM",
    ]);
  });
});

describe("filterSessions", () => {
  it("filters by IKE version", () => {
    expect(filterSessions(capture, { ikeVersion: "IKEv1" }).map((s) => s.session_id)).toEqual([
      "s-old",
    ]);
  });

  it("filters by severity", () => {
    const critical: Severity = "CRITICAL";
    expect(filterSessions(capture, { severity: critical })).toHaveLength(1);
  });

  it("searches across peer, cipher and vendor", () => {
    expect(filterSessions(capture, { search: "3des" }).map((s) => s.session_id)).toEqual(["s-old"]);
    expect(filterSessions(capture, { search: "10.0.0.10" }).map((s) => s.session_id)).toEqual([
      "s-old",
    ]);
  });

  it("keeps everything when no filter is set", () => {
    expect(filterSessions(capture, {})).toHaveLength(3);
  });
});

describe("paging", () => {
  it("reports at least one page, even when empty", () => {
    expect(pageCount(0, 25)).toBe(1);
    expect(pageCount(101, 25)).toBe(5);
  });

  it("slices the requested page", () => {
    expect(page([1, 2, 3, 4, 5], 1, 2)).toEqual([3, 4]);
  });
});

describe("peers", () => {
  it("lists each address once", () => {
    expect(peers(capture)).toEqual(["10.0.0.9", "10.0.0.2", "10.0.0.10"]);
  });
});
