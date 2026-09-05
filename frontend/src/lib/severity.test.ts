import { describe, expect, it } from "vitest";
import { bySeverity, worst } from "./severity";
import type { Severity } from "./types";

describe("severity ordering", () => {
  it("sorts worst first so what needs attention lands on top", () => {
    const input: Severity[] = ["LOW", "CRITICAL", "SAFE", "HIGH", "MEDIUM"];
    expect([...input].sort(bySeverity)).toEqual(["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]);
  });

  it("reports the worst of a peer's sessions, and SAFE for none", () => {
    expect(worst(["LOW", "HIGH", "MEDIUM"])).toBe("HIGH");
    expect(worst([])).toBe("SAFE");
  });
});
