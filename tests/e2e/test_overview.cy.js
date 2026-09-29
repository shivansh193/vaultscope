/** P4-T6: aggregate dashboard. */

function analyse(path) {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile(path, { action: "drag-drop" });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
  cy.contains("a", "Overview").click();
}

// The demo capture has real ESP in every tunnel, so every chart has data.
beforeEach(() => analyse("../data/demo/demo_capture.pcap"));

it("renders all three charts from real session data", () => {
  cy.contains("Risk distribution").should("be.visible");
  cy.get(".recharts-bar-rectangle").should("have.length.gte", 1);

  cy.contains("Traffic inside the tunnels").should("be.visible");
  cy.get(".recharts-pie-sector").should("have.length.gte", 1);

  cy.contains("Threat matrix").should("be.visible");
  cy.get("[data-testid=matrix-cell]").should("have.length", 9);
});

it("offers the same numbers as a table", () => {
  cy.contains("summary", "Show the numbers").first().click();
  cy.contains("Band").should("be.visible");
});

it("says why there is no traffic mix when no tunnel carried ESP", () => {
  analyse("../tests/e2e/fixtures/test_mixed.pcap");
  cy.get("[data-testid=traffic-empty]").should("contain", "carried ESP");
  cy.get(".recharts-pie-sector").should("not.exist");
});
