/** P4-T9: historical diff between two captures. */

function analyse(fixture) {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile(`../tests/e2e/fixtures/${fixture}`, {
    action: "drag-drop",
  });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
}

it("shows what changed between two captures", () => {
  analyse("test_weak.pcap");
  analyse("test_mixed.pcap");

  cy.contains("a", "Compare").click();
  cy.get("[data-testid=diff-run]").click();

  cy.get("[data-testid=diff-added]").should("be.visible");
  cy.get("[data-testid=diff-removed]").should("be.visible");
  cy.get("[data-testid=diff-degraded]").should("be.visible");

  // The mixed capture adds the four IKEv2 SAs the weak one does not have.
  cy.get("[data-testid=diff-added]").find("[data-testid=session-row]").should("have.length.gte", 1);
});

it("asks for a second capture rather than showing an empty comparison", () => {
  // Jobs are backend-wide; pretend this is a fresh install holding one capture.
  cy.intercept("GET", /\/jobs(\?.*)?$/, (req) =>
    req.continue((res) => {
      const jobs = typeof res.body === "string" ? JSON.parse(res.body) : res.body;
      res.send(jobs.slice(0, 1));
    }),
  ).as("jobs");
  cy.visit("/compare");
  cy.wait("@jobs");
  cy.contains("Analyse two captures").should("be.visible");
});
