/** P4-T3: session table sort, filter and risk highlight (spec Section 9). */

beforeEach(() => {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_mixed.pcap", {
    action: "drag-drop",
  });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
});

it("sorts by risk score descending", () => {
  cy.get("[data-testid=sort-risk]").click();
  cy.get("[data-testid=session-row]").first().should("have.attr", "data-severity", "CRITICAL");
});

it("highlights CRITICAL rows red", () => {
  cy.get("[data-severity=CRITICAL]")
    .should("have.css", "background-color")
    .and("match", /rgb\(24[0-9]|25[0-5]/);
});

it("filters by IKE version", () => {
  cy.get("[data-testid=filter-ike-version]").select("IKEv1");
  cy.get("[data-testid=session-row]").each((row) => {
    cy.wrap(row).find("[data-field=ike_version]").should("contain", "IKEv1");
  });
});

it("opens the drilldown with the full IKE decode and a config diff", () => {
  cy.get("[data-testid=session-row][data-severity=CRITICAL]").first().click();
  cy.get("[data-testid=session-drilldown]").should("be.visible");
  cy.get("[data-testid=session-drilldown]").contains("IKE negotiation");
  cy.get("[data-testid=config-diff]").should("be.visible");
});
