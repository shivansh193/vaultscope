import { defineConfig } from "cypress";

/**
 * The e2e specs live in tests/e2e/ alongside the Python suite, per spec
 * Section 9, and run against a real stack: uvicorn on :8000, next dev on
 * :3000, or against `docker compose up` with CYPRESS_apiBase=/api.
 */
export default defineConfig({
  e2e: {
    baseUrl: process.env.CYPRESS_BASE_URL ?? "http://localhost:3000",
    specPattern: "../tests/e2e/**/*.cy.{js,jsx,ts,tsx}",
    supportFile: "../tests/e2e/support.js",
    fixturesFolder: "../tests/e2e/fixtures",
    screenshotsFolder: "../tests/e2e/screenshots",
    videosFolder: "../tests/e2e/videos",
    video: false,
    viewportWidth: 1440,
    viewportHeight: 900,
  },
});
