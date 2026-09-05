/** P4-T8: export panel. All four artifacts build and are downloadable. */

beforeEach(() => {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_mixed.pcap", {
    action: "drag-drop",
  });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
  cy.contains("a", "Export").click();
  cy.window().then((win) => cy.stub(win, "open").as("open"));
});

for (const type of ["executive", "technical", "json", "cef"]) {
  it(`builds the ${type} artifact and offers it for download`, () => {
    cy.get(`[data-testid=export-${type}]`).click();
    cy.get(`[data-testid=download-${type}]`, { timeout: 20000 })
      .should("have.attr", "href")
      .and("include", "/report/download/");
    cy.get("@open").should("have.been.called");
  });
}

it("reports a build the backend refuses instead of opening a blank tab", () => {
  cy.intercept("POST", "**/report/*", { statusCode: 500, body: "renderer unavailable" });
  cy.get("[data-testid=export-executive]").click();
  cy.contains("could not be built").should("be.visible");
  cy.get("@open").should("not.have.been.called");
});
