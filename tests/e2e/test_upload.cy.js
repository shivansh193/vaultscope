/** P4-T2: pcap upload flow (spec Section 9). */

it("uploads pcap and redirects to session table", () => {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_weak.pcap", {
    action: "drag-drop",
  });
  cy.get("[data-testid=upload-progress]").should("be.visible");
  cy.url({ timeout: 15000 }).should("include", "/sessions");
  cy.get("[data-testid=session-row]").should("have.length.gte", 1);
});

it("reports a capture the backend rejects, without leaving the page", () => {
  cy.intercept("POST", "**/ingest", { statusCode: 500, body: "unreadable capture" }).as("ingest");
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_weak.pcap", {
    action: "drag-drop",
  });
  cy.wait("@ingest");
  cy.contains("could not be analysed").should("be.visible");
  cy.url().should("not.include", "/sessions");
});
