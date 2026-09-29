/** A live run -- here a replay, which needs no capture privilege -- streams into the console. */

afterEach(() => {
  const api = Cypress.env("apiBase") || "http://localhost:8000";
  cy.request({ method: "POST", url: `${api}/live/stop`, failOnStatusCode: false });
});

it("replays the demo capture and streams its sessions as they are found", () => {
  cy.visit("/live");
  cy.get("[data-testid=live-state]").should("have.attr", "data-state", "open");
  cy.get("[data-testid=live-source]").select("replay:demo");
  cy.get("[data-testid=live-speed]").select("1000");
  cy.get("[data-testid=live-start]").click();

  cy.get("[data-testid=live-run-state]").should("have.attr", "data-state", "running");
  cy.get("[data-testid=session-row]", { timeout: 20000 }).should("have.length.gte", 1);
  cy.get("[data-testid=live-run-state]", { timeout: 60000 }).should(
    "have.attr",
    "data-state",
    "stopped",
  );
  cy.get("[data-testid=session-row]").should("have.length", 6);

  cy.get("[data-testid=live-open-job]").click();
  cy.url().should("include", "/sessions");
  cy.get("[data-testid=session-row]").should("have.length", 6);
});
