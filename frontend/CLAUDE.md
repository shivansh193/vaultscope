# CLAUDE.md — Stage 6 dashboard (P4)

React console for the VaultScope backend. Owned by Block B (@p4ralyn).

## Commands

```bash
cd frontend
npm install
npm run dev     # http://localhost:3000, expects the backend on :8000
npm run build   # static export into frontend/out/ (nginx serves this)
npm test        # vitest, unit + component
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
- `src/components/` — shell (`Sidebar`, `Toolbar`, `BackendStatus`) and per-view components.

## Design language

Apple HIG, dark-first. Tokens live at the top of `src/app/globals.css`: Apple's dark system semantics for surfaces and labels, five severity hues, systemBlue accent. Rules that keep the console coherent:

- Severity is read by **hue**, never by a badge on every row — rows carry a 2px severity rail on the leading edge.
- Monospace (`.mono`) is for values that must align: SPIs, transforms, IPs, config diffs. Not for labels.
- Numbers in tables get `.tabular`.
- Motion answers a user action. No scroll-triggered entrances.
