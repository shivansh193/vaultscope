# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Maintaining this file

After every `git push`, review whether this file is still accurate and update it — new build/lint/test/run commands, changed architecture, new stages implemented, or stack decisions that diverged from the LLD. Keep the "Project status", "Commands", and "Tech stack" sections in sync with what actually exists in the repo. When you change something structural, also update the nearest subtree `CLAUDE.md` in the same commit.

## Project status

**Pipeline build in progress.** Environment, package skeleton, test tree and lint/test config are in place. Implemented so far:

- **Stage 2 — IKE parser** (`core/ike_parser/`, Block A / P2-T1 + P2-T2): `parse_ikev2()` and `parse_ikev1()` reconstruct IKEv2 / IKEv1-phase-1 handshakes into `core.models.VPNSession` (fills the `ike` block). See `core/ike_parser/CLAUDE.md`.
- **Stage 4c — rule engine** (`core/rules/`, Block B / P3-T1..T3): `evaluate_rules()` + `rules.yaml` + vendor remediation.
- **Stage 5 — reports** (`reporting/`, Block B / P3-T4..T6): executive/technical reports, JSON/CEF export.
- **Backend API + pipeline** (`api/`, `core/pipeline.py`, `core/anomalies.py`, Block B / P3-T7..T10): every route in spec Section 11, SQLite persistence, cross-session anomaly detection, and `analyze_capture()` — the one seam onto Block A. P3 is complete.

- **Stage 6 — dashboard** (`frontend/`, Block B / P4-T1..T6): Next.js console — capture upload, session table, drilldown panel, D3 peer graph, aggregate charts. Live mode, export and diff land in P4-T7..T9.

Not yet started: Stage 0 testbed, Stage 1 ingestion, Stage 3 flow features, Stage 4a/4b classifiers.

The design artifacts are `SIH26160_LLD.md` (Low-Level Design, SIH 2026 PS SIH26160) and `docs/VaultScope_Product_Spec.docx`. Read the LLD first; it is the single source of truth for scope and architecture, and its section numbering is shared vocabulary (e.g. "Stage 4b", "Section 3.6").

Work is split across four async slices (P1–P4), grouped into two engineer blocks: Block A (@shivansh193) owns P1+P2 (Stages 0–4b), Block B (@p4ralyn) owns P3+P4 (Stages 4c–6). `README.md` maps each directory to its stage and owner. Don't edit the other block's directories without coordinating.

## Commands

```bash
# setup (Python 3.11; see README for tshark / pango system deps)
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

pytest                      # whole suite from repo root
pytest tests/ike_parser     # one slice
pytest -m "not slow"        # skip tests needing the full dataset / trained model
ruff check . && ruff format --check .

uvicorn api.main:app --reload   # backend on :8000; Swagger UI at /docs
python scripts/generate_mock_data.py   # regenerate data/mock/*.json

cd frontend && npm install && npm run dev   # console on :3000; see frontend/CLAUDE.md
```

`VAULTSCOPE_DB` overrides the SQLite path (default `vaultscope.sqlite` at the repo root) and `VAULTSCOPE_REPORT_DIR` the report output directory; the API tests set both to a `tmp_path`.

`pyproject.toml` sets `pythonpath = ["."]`, so `import core.ike_parser` works with no install step. `tests/test_environment.py` is the environment smoke test — it asserts the directory skeleton, the importable dependency set, and `tshark` on PATH. Keep its skeleton list current when directories are added.

## Working agreement

- **One PR per task ID** from the spec's commit map (`P2-T1`, `P2-T2`, …). Branch `feat/<taskid>-<slug>`, commit subject `feat(<area>): <what>` matching the commit-map line. Every task ships with its mandatory test passing.
- **Stacked PRs**: a task that builds on an unmerged task branches off that branch, not `main`; rebase onto `main` once the parent merges.
- Do **not** add `Co-Authored-By: Claude` trailers to commits.
- Run `pytest -q` and `ruff check . && ruff format --check .` before every commit.

## Subtree guides

- `frontend/CLAUDE.md` — Stage 6 console: commands, stack divergences from the LLD, design tokens.
- `core/ike_parser/CLAUDE.md` — Stage 2 IKE parser: module map, wire-format gotchas, `IkeParams` mapping, task status.

## What this system is

An **AI-powered IPsec VPN protocol analyzer and security assessment framework**. It is *not* a live-network monitor. The pipeline is:

1. Generate a **labeled dataset** in a self-hosted lab: spin up IPsec tunnels across a config matrix and inject known traffic types through them, capturing pcaps with ground-truth labels. The dataset itself is an explicit deliverable.
2. Ingest a capture (uploaded pcap or live NIC) and analyze it across the stages below.

There are **two distinct AI problems of very different difficulty** — keep them separate in code and in any explanation:
- **Protocol/crypto identification (Stage 4a)** is *mostly deterministic*: IKE negotiation declares these params in cleartext, so this is a parser-first component with light ML only for malformed/ambiguous/truncated handshakes. Do not over-model this.
- **Traffic-type-inside-ESP prediction (Stage 4b)** is the *genuine ML showpiece*: ESP payloads are encrypted, so classification relies purely on metadata side-channels (packet size distribution, inter-arrival timing, direction ratio, burstiness). This is where modeling effort belongs.

## Architecture (staged pipeline)

Data flows Stage 0 → 6. Stages 4a/4b/4c run in parallel off the parsed session + extracted flow features, then converge at Stage 5.

- **Stage 0 — Testbed** (offline, one-time): strongSwan peers in Docker Compose / Linux netns, scripted over the cartesian config matrix `{tunnel,transport} × {AES-128, AES-256, AES-GCM, AES-CBC+HMAC-SHA256} × {MODP1024, MODP2048, ECP256} × {PFS on/off} × {IPv4, IPv6}`. Traffic generators (sipp/RTP, ffmpeg, curl/headless Chrome, Postfix+swaks, ping) ride each tunnel. Output: one pcap per (config, traffic-type) + a metadata JSON label.
- **Stage 1 — Ingestion**: `pyshark` (tshark) for structured fields, `scapy` fallback for raw parsing. Filters IKE (`udp.port==500 or udp.port==4500`) and data-plane (`esp or ah`). Buckets into sessions keyed by `(init_SPI, resp_SPI)` for IKEv2 / `(cookie_i, cookie_r)` for IKEv1.
- **Stage 2 — IKE parser** (deterministic): reassembles the handshake, extracts version/mode/encryption/integrity/prf/dh_group/pfs/lifetime/ip_version. IKEv1 vs IKEv2 parse different payload structures; PFS is inferred from a second DH exchange (`CREATE_CHILD_SA` / Quick Mode KE payload).
- **Stage 3 — Flow feature extractor**: metadata-only per-flow stats (grouped by SPI + 5-tuple) via `nfstream` or a custom scapy aggregator. These vectors are the input to Stage 4b.
- **Stage 4a/4b/4c** — protocol classifier / traffic-type classifier / security rule engine (see below).
- **Stage 5 — Scoring & report aggregator**: merges 4a+4b+4c per session into one record; produces risk score, threat matrix, AI confidence score, and Jinja2→PDF executive + technical reports (WeasyPrint or ReportLab).
- **Stage 6 — Dashboard**: React + Tailwind + Recharts. Can be built against mocked JSON before the backend exists.

## Canonical data model

The persisted per-session record (LLD Section 5) is the contract that glues stages together — the IKE parser, classifiers, rule engine, DB, API, and frontend all agree on this shape (`core/models.py`). Match its field names and nesting (`ike`, `traffic_prediction`, `security_assessment`, `reports`) rather than inventing new ones; **do not define a second shape for a session anywhere.** The rule engine's checks (weak cipher, MODP768/1024, IKEv1 Aggressive Mode, PFS off, long SA lifetime, replay protection off) map directly onto `ike.*` fields and are defined as data (YAML/JSON), not hardcoded logic.

## Tech stack

Backend FastAPI; DB SQLite (hackathon) / PostgreSQL (scale); ML scikit-learn (RandomForest/XGBoost baseline, optional PyTorch 1D-CNN stretch); reports Jinja2 + WeasyPrint/ReportLab; frontend Next.js (App Router, static export) + Tailwind v4 + Recharts + D3, tested with Vitest; whole stack containerized via Docker Compose.

Python deps are pinned across three manifests: `requirements.txt` (runtime), `requirements-dev.txt` (adds pytest/ruff/httpx), and `requirements-stretch.txt` (`torch`, `nfstream` — install only when working that stretch goal; `nfstream` is an accelerator, the custom scapy aggregator is the primary Stage 3 path). `requirements.lock.txt` is a known-good `pip freeze` to fall back on if resolution conflicts. The frontend and DB layers have no manifest yet.

## Working principles specific to this project (from the LLD's own callouts)

- **Report ML honestly.** ESP traffic-type prediction is side-channel inference; accuracy will not be 100%. Produce a confusion matrix rather than overclaiming.
- **The "WhatsApp" class is a substitution** — it can't run in an isolated lab, so it's approximated with a bursty chat-sized generator. Keep this labeled as such; don't present it as real WhatsApp traffic.
- **The dataset is lab-clean** (no cross-traffic noise), so real-world accuracy will be lower — treat this as a documented limitation, not something to hide.

## Change log (newest first)

- **P4-T5..T6** Peer graph and aggregate dashboard — D3 force graph (`PeerGraph`) with peers as nodes coloured by their worst session, draggable, click-through to the filtered table or the session itself; Recharts risk histogram, traffic donut and a threat-matrix heatmap on `/overview`. Chart palettes live in `src/lib/charts.ts`: severity stays a status scale, traffic type gets its own validated categorical scale (Apple's hues failed CVD separation and were replaced). Every chart carries a tooltip and a table of the same numbers.
- **P4-T2..T4** Upload, session table, drilldown — `UploadDrop` posts to `/ingest` and redirects; `SessionTable` sorts, filters and pages client-side over the capture's sessions; `SessionDrilldown` is a panel, not a route. `CaptureSpectrum` shows the whole capture as one strip of severity segments. Views are scoped to the current `job_id` so a table never mixes captures. Cypress specs from spec Section 9 live in `tests/e2e/` with generated pcap fixtures (`scripts/generate_e2e_fixtures.py`).
- **P4-T1** Console scaffold — Next.js 16 App Router + TypeScript + Tailwind v4 in `frontend/`, `output: "export"` so nginx serves static files. `src/lib/types.ts` mirrors `core/models.py`, `src/lib/api.ts` is the only place that calls the backend, `src/app/globals.css` holds the Apple-dark design tokens. Vitest for units. See `frontend/CLAUDE.md`.
- **P3-T7..T10** FastAPI backend, pipeline, SQLite store, anomalies — `api/main.py` (spec Section 11 routes + `/ws/live`), `api/store.py`, `core/pipeline.py`, `core/anomalies.py`. `analyze_capture()` probes each Block A stage independently and falls back to FIXTURE MODE off `data/mock/sessions.json`, stamping `capture_complete=False` / `model_version="fixture"`. Both `parse_ikev2_sessions` and `parse_ikev1_sessions` are called per capture — they already emit canonical `VPNSession`, so the pipeline adds Stage 3/4b/4c on top rather than reshaping the record. `pyproject.toml`: FastAPI argument-default markers exempted from ruff's B008.
- **P2-T2** IKEv1 / ISAKMP parser — `parse_ikev1()`, Main vs Aggressive Mode detection (ID-payload-in-message-1 signal, not message count), phase-1 crypto extraction. `core/ike_parser/ikev1.py`, `V1_*` constants + `canon_v1_*` in `_transforms.py`.
- **P2-T1** IKEv2 parser — `parse_ikev2()`, SA_INIT + IKE_AUTH → `core.models.VPNSession`. Pure-`struct` RFC 7296 wire decoder (`_wire.py`), IANA canonicalisation (`_transforms.py`). Widened `core.models.IkeParams.auth_method` to also accept `DSS` / `ECDSA` / `None` (real IKE auth methods beyond the spec's 4-value enum).
- **Env setup** — repo skeleton per spec §3.2, Python tooling, smoke tests.
