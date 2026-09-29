/** Runtime anomalies reach the console with the frames that prove them. */

beforeEach(() => {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_mixed.pcap", {
    action: "drag-drop",
  });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
});

it("lists attack indicators with evidence frame numbers", () => {
  cy.get("[data-testid=anomaly-list]").should("be.visible");
  cy.get("[data-testid=anomaly][data-type=AGGRESSIVE_MODE_PROBE]")
    .find("[data-testid=evidence-frames]")
    .should("contain", "frames 9, 10");
  cy.get("[data-testid=anomaly-flag]").should("have.length.gte", 1);
});

it("hands over the capture those frames index into", () => {
  cy.get("[data-testid=download-capture]")
    .should("have.attr", "href")
    .then((href) => cy.request(href).its("status").should("eq", 200));
});

it("shows a session's own anomalies in its drilldown", () => {
  cy.get("[data-testid=anomaly][data-type=AGGRESSIVE_MODE_PROBE]").contains("open session").click();
  cy.get("[data-testid=session-anomalies]").should("contain", "Aggressive mode probe");
});
