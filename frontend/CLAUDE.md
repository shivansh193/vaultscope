# CLAUDE.md — Stage 6 dashboard (P4)

React console for the VaultScope backend. Owned by Block B (@p4ralyn).

## Commands

```bash
cd frontend
npm install
npm run dev     # http://localhost:3000, expects the backend on :8000
npm run build   # static export into frontend/out/ (nginx serves this)
npm test        # vitest, unit + component
npm run e2e     # cypress; needs uvicorn on :8000 and next dev on :3000
npm run lint
```

`NEXT_PUBLIC_API_BASE` points the bundle at a backend (default `http://localhost:8000`). It is read at build time for the static export, so the Docker image is built per environment.

## Stack decisions that diverge from the LLD

- **Next.js App Router, not React Router.** The LLD says "React + React Router"; App Router covers the same routing need and is what `create-next-app` gives, so there is no router dependency.
- **`output: "export"`.** The console is entirely client-side, so the build is static files and the frontend container is nginx alone — no Node runtime.
- **Session drilldown is a panel, not a `/session/[id]` route.** Session ids are only known at runtime, which a static export cannot enumerate. The panel also keeps the table in view while reading a session.

## Structure

- `src/lib/types.ts` — the TypeScript view of `core/models.py`. The Python model is the source of truth; mirror names and nesting exactly and never invent a field the backend does not send.
- `src/lib/api.ts` — every backend call, typed. Nothing else calls `fetch`.
- `src/lib/severity.ts` — severity ordering and the hue mapping.
- `src/lib/useLiveSessions.ts` — the `/ws/live` socket. Newest first, deduplicated by `session_id`.
- `src/lib/job.ts` — the captures this browser has analysed, in `sessionStorage`. Export and Compare read their options from it.
- `src/lib/charts.ts` — chart palettes and the pure shaping functions (`riskHistogram`, `trafficMix`, `threatMatrix`, `peerGraph`).
- `src/components/` — shell (`Sidebar`, `Toolbar`, `BackendStatus`) and per-view components.
- `src/test/factory.ts` — session builder for tests: canonical defaults, override only what the test is about.
- `../tests/e2e/` — Cypress specs from spec Section 9, run against a real stack. See `tests/e2e/README.md`.

## Behaviour worth knowing

- **Views are scoped to the most recent ingest.** The database accumulates every capture ever uploaded; `useSessions()` filters by the current `job_id` so a table never mixes three captures. `useSessions({ allCaptures: true })` opts out — the compare view needs it.
- **The table opens sorted worst-first.** Clicking the Risk header the first time re-asserts that order rather than reversing it; reversing on the first click would hide exactly what the user opened the capture to see.
- **Data-`testid` and `data-field` attributes on rows are contract**, not decoration — the Cypress specs in the spec's commit map select on them.

## Design language

Apple HIG, dark-first. Tokens live at the top of `src/app/globals.css`: Apple's dark system semantics for surfaces and labels, five severity hues, systemBlue accent. Rules that keep the console coherent:

- Severity is read by **hue**, never by a badge on every row — rows carry a 2px severity rail on the leading edge.
- Monospace (`.mono`) is for values that must align: SPIs, transforms, IPs, config diffs. Not for labels.
- Numbers in tables get `.tabular`.
- **Two colour scales, never mixed in one chart.** Severity is a *status* scale (`src/lib/severity.ts`, Apple's system reds through green). Traffic type is a *categorical* scale (`src/lib/charts.ts`) with a fixed slot order — a capture missing VoIP must not repaint Web in VoIP's hue. Apple's own hues were tried for traffic and failed colourblind separation on this surface (blue/purple ΔE 4.3 protan); the current seven pass all six checks. Re-run the validator before changing any of them.
- Charts ship a tooltip and a "Show the numbers" table. A chart nobody can read the values off is half a chart.
- Motion answers a user action. No scroll-triggered entrances.

<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
