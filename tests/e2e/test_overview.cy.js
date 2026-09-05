/** P4-T6: aggregate dashboard. */

beforeEach(() => {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_mixed.pcap", {
    action: "drag-drop",
  });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
  cy.contains("a", "Overview").click();
});

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
