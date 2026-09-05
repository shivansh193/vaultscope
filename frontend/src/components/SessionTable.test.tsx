import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SessionTable } from "./SessionTable";
import { sortSessions } from "@/lib/sessions";
import { session } from "@/test/factory";

const capture = [
  session("s-safe", { severity: "SAFE", score: 100 }),
  session("s-bad", { severity: "CRITICAL", score: 20, version: "IKEv1", encryption: "3DES-CBC" }),
];

function renderTable(sessions = capture, onSelect = vi.fn()) {
  render(
    <SessionTable
      sessions={sessions}
      sort="risk"
      direction="asc"
      onSort={vi.fn()}
      onSelect={onSelect}
    />,
  );
  return onSelect;
}

describe("SessionTable", () => {
  it("tints CRITICAL rows red so they are found by scanning, not by reading", () => {
    renderTable();
    const critical = screen.getByText("3DES-CBC").closest("tr")!;
    expect(critical).toHaveAttribute("data-severity", "CRITICAL");
    expect(critical.style.background).toContain("255, 69, 58");
  });

  it("leaves healthy rows untinted", () => {
    renderTable();
    const safe = document.querySelector('[data-severity="SAFE"]') as HTMLElement;
    expect(safe.style.background).toBe("");
  });

  it("exposes the fields the peer graph and e2e specs filter on", () => {
    renderTable();
    const row = document.querySelector('[data-severity="CRITICAL"]')!;
    expect(row.querySelector('[data-field="ike_version"]')).toHaveTextContent("IKEv1");
    expect(row.querySelector('[data-field="initiator_ip"]')).toHaveTextContent("10.0.0.1");
    expect(row.querySelector('[data-field="responder_ip"]')).toHaveTextContent("10.0.0.2");
  });

  it("opens a session when its row is clicked", async () => {
    const onSelect = renderTable();
    await userEvent.click(screen.getByText("3DES-CBC"));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ session_id: "s-bad" }));
  });

  it("renders a hundred rows in worst-first order", () => {
    const many = Array.from({ length: 100 }, (_, i) =>
      session(`s-${i}`, { severity: i === 73 ? "CRITICAL" : "LOW", score: i }),
    );
    renderTable(sortSessions(many, "risk"));
    const rows = screen.getAllByTestId("session-row");
    expect(rows).toHaveLength(100);
    expect(rows[0]).toHaveAttribute("data-severity", "CRITICAL");
  });

  it("invites the user to widen filters instead of showing an empty grid", () => {
    renderTable([]);
    expect(screen.getByText(/no sessions match these filters/i)).toBeInTheDocument();
  });
});
