/** P4-T7: live session stream over /ws/live (spec Section 9). */

const API = Cypress.env("apiBase") || "http://localhost:8000";

/** Analyse a capture out-of-band, the way a second operator would. */
function ingestElsewhere(win, fixture) {
  return cy.fixture(fixture, "binary").then((binary) => {
    const blob = Cypress.Blob.binaryStringToBlob(binary);
    const form = new FormData();
    form.append("file", blob, fixture);
    return win.fetch(`${API}/ingest`, { method: "POST", body: form });
  });
}

it("new session appears in the table within 2 seconds of a backend detection", () => {
  cy.visit("/live");
  cy.get("[data-testid=live-state]").should("have.attr", "data-state", "open");
  cy.get("[data-testid=live-empty]").should("be.visible");

  cy.window().then((win) => ingestElsewhere(win, "test_weak.pcap"));

  cy.get("[data-testid=session-row]", { timeout: 2000 }).should("have.length.gte", 1);
  cy.get("[data-testid=session-row]").first().should("have.attr", "data-severity", "CRITICAL");
});

it("clears the stream on request without dropping the connection", () => {
  cy.visit("/live");
  // The socket has to be listening before the ingest, or the event it would
  // have carried is gone.
  cy.get("[data-testid=live-state]").should("have.attr", "data-state", "open");
  cy.window().then((win) => ingestElsewhere(win, "test_weak.pcap"));
  cy.get("[data-testid=session-row]", { timeout: 4000 }).should("exist");

  cy.contains("button", "Clear").click();
  cy.get("[data-testid=live-empty]").should("be.visible");
  cy.get("[data-testid=live-state]").should("have.attr", "data-state", "open");
});
