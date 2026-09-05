// Cypress loads this before every spec. The console is a read-only analyser,
// so there is nothing to seed or clean up -- but an uncaught ResizeObserver
// notice from Recharts must not fail an otherwise green run.
Cypress.on("uncaught:exception", (error) => !/ResizeObserver/.test(error.message));
