/** P4-T5: D3 peer graph (spec Section 9). */

beforeEach(() => {
  cy.visit("/");
  cy.get("[data-testid=pcap-drop]").selectFile("../tests/e2e/fixtures/test_mixed.pcap", {
    action: "drag-drop",
  });
  cy.url({ timeout: 15000 }).should("include", "/sessions");
  cy.contains("a", "Peers").click();
  cy.get("[data-testid=graph-node]").should("exist");
});

it("renders a node per unique peer IP", () => {
  // The fixture's SAs all run between the same two addresses.
  const expectedPeers = 2;
  cy.get("[data-testid=graph-node]").should("have.length", expectedPeers);
});

it("CRITICAL node has red fill", () => {
  cy.get("[data-testid=graph-node][data-severity=CRITICAL]")
    .invoke("attr", "fill")
    .should("match", /^#[Ff][0-9a-fA-F]{5}$|red/);
});

it("clicking node filters session table to that peer", () => {
  cy.get("[data-testid=graph-node]").first().click();
  cy.url().should("include", "/sessions?peer=");
  cy.get("[data-testid=session-row]").each((row) => {
    cy.wrap(row)
      .find("[data-field=initiator_ip],[data-field=responder_ip]")
      .should("contain", "192.168");
  });
});

it("clicking a session line opens that session", () => {
  cy.get("[data-testid=graph-edge]").first().click({ force: true });
  cy.url().should("include", "/sessions?session=");
  cy.get("[data-testid=session-drilldown]").should("be.visible");
});
