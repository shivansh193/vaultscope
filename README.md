# VaultScope

**AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework**
SIH 2026 · Problem Statement SIH26160 · NTRO

**Demo video:** <VIDEO-URL-PLACEHOLDER> · **Dataset:** [`data/DATASHEET.md`](data/DATASHEET.md)

VaultScope is a passive-first, active-capable IPsec VPN security intelligence
platform: it ingests traffic at the packet level, reconstructs the cryptographic
negotiation state of every VPN session, scores each session against a
CVE-linked rule database, classifies the traffic type running inside each
encrypted tunnel, and produces layered reports with vendor-specific remediation.

Full design: [`docs/VaultScope_Product_Spec.docx`](docs/VaultScope_Product_Spec.docx).

---

## Repository layout

| Path | Stage | Owner |
|---|---|---|
| `testbed/` | Stage 0 — testbed & dataset generator | A |
| `core/capture.py` | the one pcap reader: IKE + ESP frames with frame number, time, peers | A |
| `core/ingestion/` | Stage 1 — ingestion engine (buckets frames into SAs) | A |
| `core/ike_parser/` | Stage 2 — IKEv1/v2 parser | A |
| `core/flow/` | Stage 3 — ESP flow feature extractor | A |
| `core/classifiers/` | Stage 4a/4b — protocol + traffic-type ML | A |
| `core/rules/` | Stage 4c — security rule engine | B |
| `core/pipeline.py` | the Analysis module: capture in, sessions + anomalies + stats out | B |
| `core/anomalies.py` | cross-session runtime attack detectors | B |
| `core/live.py` | live capture sources: `dumpcap` on a NIC, or replay of a stored capture | B |
| `reporting/` | Stage 5 — scoring + report aggregator | B |
| `api/` | FastAPI backend, job store, live-run driver, WebSocket | B |
| `frontend/` | Stage 6 — React dashboard | B |
| `data/` | dataset: pcaps + ground-truth JSONs | A |
| `models/` | trained model artifacts + eval metrics | A |
| `tests/` | mirrors the slices above; run with `pytest` | both |
| `docs/` | product spec + API reference + setup guide | both |

Every stage reads and writes the one data model in `core/models.py` (spec
Section 5); the API follows spec Section 11 and publishes its own reference at
`/docs`.

## How a capture flows

```
pcap ──► core.capture.read_capture ──► one read: IkeFrame[] + EspFrame[]
              │
              ├─► Stage 1  bucket into IKE SAs, attach each SA's ESP by peer pair
              ├─► Stage 2  parse each SA with its own frames, times, ports, ESP
              ├─► Stage 4a fill any field the handshake hid (marked "inferred")
              ├─► Stage 3  flow features from the same ESP frames
              ├─► Stage 4b traffic type (or "no ESP seen" -- never a zero-vector guess),
              │            top contributing features, "uncertain" below 0.6 confidence
              ├─► mode     tunnel/transport inferred from ESP sizes when IKE hid it (marked inferred)
              ├─► Stage 4c 21 CVE-linked rules → risk score + findings + fixes
              ├─► metadata exposure score + 6 compliance baselines + PQC readiness
              └─► anomalies across sessions, each citing pcap frame numbers
                        │
                        ▼
                 Analysis ──► job store (SQLite) ──► API / WebSocket / reports
```

`core.pipeline.analyze_capture(path)` is the whole thing. Uploads and live
runs both go through it; nothing downstream assembles part of a result itself.

## What each session's assessment holds

| PS term | Field | Where |
|---|---|---|
| Risk Score | `security_assessment.risk_score` (0–100, higher is safer) | `core/rules/engine.py` |
| Threat Matrix | `security_assessment.threat_matrix` | same |
| AI Confidence Score | `traffic_prediction.confidence`, `abstained`, `top_features` | `core/classifiers/` |
| Key exchange method | `ike.dh_group`, `ike.pqc_status`, `ike.additional_key_exchanges` (RFC 9370 / ML-KEM) | `core/ike_parser/` |
| Security Association characteristics | `ike.*` (mode, cipher, integrity, PRF, lifetime, anti-replay, DPD, NAT-T) | same |
| Metadata exposure | `security_assessment.metadata_exposure`: 0–100 score + signals (traffic type, identity, implementation, endpoints, timing) | `core/exposure.py` |
| Configuration compliance | `security_assessment.compliance`: pass / fail / not assessed against NIST SP 800-77r1, NIST SP 800-131A, BSI TR-02102-3, CNSA 2.0, CERT-In and TEC ITSAR (the last two indicative) | `core/rules/compliance.yaml` |

Exposure is reported beside the Risk Score, not inside it: what IPsec leaks by
design is not a misconfiguration. Compliance never fails a session on a field
the capture hid; the requirement is listed as not assessed instead.

Every stored analysis is appended to a SHA-256 hash chain (`audit_log` in the
job store) that commits to the analysis digest and the capture's hash.
`GET /audit/verify` detects an edited result or rewritten history. It is
tamper-evident, not tamper-proof: publish the head hash if you need to show
later that nothing changed.

## Prerequisites

- Python **3.11**
- `dumpcap` (ships with Wireshark / tshark) — only for live capture on a real interface
- `pango` + `cairo` (runtime dependency of `weasyprint`, Stage 5)
- Docker + Docker Compose (Stage 0 testbed, full-stack demo)
- Node 18+ (Stage 6 frontend)

### System dependencies

```bash
# macOS
brew install wireshark pango           # pango pulls in cairo + glib
# Wireshark.app installs tshark but does not put it on PATH:
ln -sf /Applications/Wireshark.app/Contents/MacOS/tshark /opt/homebrew/bin/tshark

# Debian / Ubuntu
sudo apt install tshark libpango-1.0-0 libpangoft2-1.0-0
```

On macOS, `weasyprint` looks for pango/cairo only in the system library paths,
so an otherwise-correct Homebrew install raises `OSError: cannot load library
'gobject-2.0-0'`. `reporting.ensure_native_libs()` (called on `import
reporting`) points it at Homebrew's `lib` dir — no per-shell `export` needed.

## Setup

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# POSIX:    source .venv/bin/activate

pip install -r requirements-dev.txt      # full stack + test tooling
```

`requirements.lock.txt` is a full `pip freeze` of a known-good resolve
(Python 3.11) — use it (`pip install -r requirements.lock.txt`) if you hit a
dependency-resolution conflict.

> `pydyf` is pinned to `0.10.0` on purpose: `weasyprint==62.3` uses the
> pre-0.11 `pydyf` Stream API, and a floating `pydyf` installs cleanly but then
> fails at `write_pdf()` call time. `tests/test_environment.py` covers this.

`requirements.txt` is the full team manifest. Optional/stretch backends
(`torch` for the 1D-CNN, `nfstream` for flow acceleration) are in
`requirements-stretch.txt` — install only when working on that stretch goal.

### System dependencies (not installed by pip)

| Tool | Needed by | Install |
|---|---|---|
| `dumpcap` | live interface capture (`core/live.py`) | macOS `brew install wireshark` (plus Wireshark's ChmodBPF for capture rights) · Debian/Ubuntu `apt install tshark` · Windows: install Wireshark, add to PATH |
| pango / glib | `weasyprint`, Stage 5 reports | macOS `brew install pango libffi` · Debian/Ubuntu `apt install libpango-1.0-0 libpangoft2-1.0-0` · Windows: GTK runtime |

> **macOS (Apple Silicon):** `brew install pango libffi` is enough — importing
> `reporting` first fixes the library lookup in-process (`ctypes.util.find_library`
> does not search `/opt/homebrew/lib`). Always `import reporting` before
> `import weasyprint`; no shell export needed.

> On Windows, `weasyprint` (Stage 5, Block B) needs the GTK runtime. Block A
> work does not require it; install the Block A subset if the full install fails on your box:
> `pip install scapy scikit-learn xgboost numpy pandas matplotlib joblib pyyaml pytest pytest-cov`

## Running the whole stack

```bash
docker compose up --build      # then open http://localhost:3000
```

Two containers: `backend` (FastAPI, tshark, weasyprint) and `frontend` (the
console built to static files and served by nginx). nginx proxies `/api/` to
the backend, so the console talks to it same-origin — nothing has to know the
backend's address and no request needs a CORS preflight. `/api/ws/live` is
proxied as a WebSocket.

Analysed captures and rendered reports live on the `vaultscope-data` volume and
survive a rebuild. `docker compose down -v` throws them away.

To run the pieces separately during development:

```bash
uvicorn api.main:app --reload           # backend on :8000, Swagger at /docs
cd frontend && npm run dev              # console on :3000
```

### Hosted demo (Render + Vercel)

The API runs on Render from the same Dockerfile; the console is a static build
on Vercel that talks to it cross-origin.

1. **API on Render:** New → Blueprint → this repository. `render.yaml` turns
   interface capture off, caps uploads at 50 MB and generates an operator token.
   Note the service URL, e.g. `https://vaultscope-api.onrender.com`.
2. **Console on Vercel:** from `frontend/`, deploy with the API URL baked in:
   `vercel deploy --prod -e NEXT_PUBLIC_API_BASE=<render url> --build-env NEXT_PUBLIC_API_BASE=<render url>`.
3. Back on Render, set `VAULTSCOPE_CORS_ORIGINS` to the Vercel URL and redeploy.

Render's free plan sleeps after inactivity (the first request takes ~a minute)
and keeps no disk, so hosted jobs are temporary. For the full product — live
interface capture, persistent jobs — run `docker compose up` on the analysis box.

### Configuration

Environment only, so the same image runs in dev, Compose and CI.

| Variable | Default | What it controls |
|---|---|---|
| `VAULTSCOPE_DB` | `vaultscope.sqlite` | SQLite database |
| `VAULTSCOPE_CAPTURE_DIR` | `data/captures/` | analysed captures, kept so evidence frames can be checked |
| `VAULTSCOPE_KEEP_CAPTURES` | `1` | set `0` to delete each upload after analysis |
| `VAULTSCOPE_REPORT_DIR` | `reporting/out/` | rendered reports |
| `VAULTSCOPE_MAX_UPLOAD_MB` | `512` | upload size cap (413 above it) |
| `VAULTSCOPE_CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | browser origins allowed to call the API (comma-separated). Compose needs none: nginx serves the console same-origin |
| `VAULTSCOPE_API_TOKEN` | unset (open) | operator token for deleting jobs and interface capture, sent as `X-VaultScope-Token`; uploads and replays stay open |
| `VAULTSCOPE_INTERFACE_CAPTURE` | `1` | `0` turns off live capture on real NICs (public deployments) |
| `NEXT_PUBLIC_API_BASE` | `http://localhost:8000` | where the console finds the API (build time) |

### Live capture

The **Live** page starts a run from one of two sources behind the same seam
(`core/live.py`), and either way sessions and anomalies stream in over
`/ws/live` and the run is saved as a job:

- **Replay** a stored capture — the bundled `data/demo/demo_capture.pcap` or any
  upload — at a chosen speed. Needs no privileges; it is what the demo and the
  tests use.
- **Interface** — `dumpcap` on a real NIC, filtered to IKE/ESP/AH. Needs capture
  rights: Wireshark's ChmodBPF on macOS, `CAP_NET_RAW` on Linux. In Docker on a
  Linux host: `docker compose -f docker-compose.yml -f docker-compose.live.yml up`.

The run re-analyses its growing capture every two seconds, so an SA whose
handshake and ESP land in different ticks is still one session, and every
evidence frame number points into a file you can download from the job.

### API at a glance

Full reference with schemas at `/docs` (Swagger) and `/openapi.json`.

| Route | Purpose |
|---|---|
| `POST /ingest` | analyse an uploaded pcap / pcapng → new job (415 if not a capture, 413 if too big) |
| `GET /jobs` · `GET /jobs/{id}` · `DELETE /jobs/{id}` | analysed captures with severity mix, posture, anomaly count, stats |
| `GET /jobs/{id}/capture` | the exact capture a job analysed — evidence frames index into it |
| `GET /sessions?job_id=&severity=` · `GET /session/{id}` | assessed sessions |
| `GET /events?job_id=` | runtime anomalies, worst first, with evidence frames |
| `GET /sessions/diff?base_job=&compare_job=` | new / gone / degraded sessions between two captures |
| `POST /report/{job_id}` | executive PDF, technical HTML, JSON or CEF |
| `GET /rules` | the 21-rule table |
| `POST /simulate` | what-if: re-score a stored session with cipher / DH / PFS / mode changed; nothing is stored |
| `GET /audit` · `GET /audit/verify` | hash-chained log of every stored analysis; verify recomputes the chain and each job's digest |
| `POST /live/start` · `POST /live/stop` · `GET /live/status` · `GET /live/interfaces` | live runs |
| `WS /ws/live` | `{"type": "session" \| "session_removed" \| "anomaly" \| "anomaly_removed" \| "live", ...}` as they happen; `*_removed` retracts a record a later tick superseded |

## Running tests

```bash
pytest                 # whole suite from repo root
pytest tests/ike_parser # one slice
pytest -m "not slow"   # skip tests needing the full dataset / trained model

ruff check . && ruff format --check .
```

`tests/test_environment.py` is the environment smoke test: it asserts the
directory skeleton, the importable dependency set, `dumpcap` for live capture,
a `scapy` → `core.capture` pcap round-trip, and `weasyprint` PDF rendering.
Run it first on a new box.

CI (`.github/workflows/ci.yml`) runs ruff and pytest (minus the Docker testbed
and the 129 MB corpus), the console's lint, types, vitest and build, and the
Cypress suite against a real backend on every push.

`pyproject.toml` sets `pythonpath = ["."]`, so `import core.ike_parser` works
with no install step.

The frontend has its own suites:

```bash
cd frontend
npm test        # vitest: unit + component
npm run e2e     # cypress, against a running backend on :8000 and console on :3000
```

The Cypress specs in `tests/e2e/` drive a real stack rather than a mock, so a
green run means the browser, the API and the parser all agree. Their pcap
fixtures are generated — rebuild with `python scripts/generate_e2e_fixtures.py`.

### Demo captures

| File | What it is |
|---|---|
| `data/demo/demo_capture.pcap` | six real strongSwan tunnels from the dataset, weak through strong, all six traffic classes (`scripts/make_demo_capture.py`) |
| `data/demo/attack_capture.pcap` | a **synthetic** gateway-under-attack capture built from the parser's test builders; trips five anomaly detectors (`scripts/make_attack_capture.py`) |

## Deliverables

Spec Section 13. Status as of the latest commit on `main`.

| # | Deliverable | Owner | Status |
|---|---|---|---|
| 1 | Labeled dataset (>= 300 pcaps + JSONs) | P1 | Done — 300 captures, all six classes, `data/README.md` |
| 2 | Trained model artifacts | P2 | Done — trained on the captured dataset (`source: pcap-dataset`). Read the accuracy caveat below before quoting the number. |
| 3 | Working prototype (`docker compose up`) | P4 | Done |
| 4 | Executive PDF report | P3 | Done |
| 5 | Technical HTML report | P3 | Done |
| 6 | JSON / CEF export | P3 | Done |
| 7 | Dashboard demo | P4 | Done |
| 8 | Demo video (3-5 min) | All | Done — <VIDEO-URL-PLACEHOLDER> |
| 9 | Product spec | All | Done — `docs/VaultScope_Product_Spec.docx` |
| 10 | API reference (Swagger) | P3 | Done — `/docs` on the backend |
| 11 | Setup guide | P4 | Done — this file |
| 12 | Disclosed limitations | All | Done — below |

## Disclosed limitations

Read these before quoting any number this system produces.

**The traffic-type prediction is inference, not observation.** ESP payloads are
encrypted and stay that way. Stage 4b infers what rode a tunnel from packet
sizes, timing, direction ratio and burstiness alone. It will be wrong sometimes;
results are reported as a confusion matrix rather than a single accuracy figure.

**The "Chat" class is a substitution.** A real messaging client cannot run in an
isolated lab, so chat traffic is a scripted generator reproducing the shape —
short messages in bursts with long idle gaps. Every Chat label carries
`"substitution": true`. It is not real WhatsApp traffic and must not be
presented as such.

**The reported classifier accuracy is an upper bound, not a field number.**
Stage 4b scores macro-F1 **0.98** on a held-out split of the captured dataset,
up from 0.79 on the synthetic bootstrap it replaced. That number should be read
with its dataset in mind rather than quoted on its own. Each capture holds
exactly one traffic class, produced by a deterministic generator at a fixed
rate, so the classes separate on coarse statistics alone — median packet count
runs from 36 (Chat) to 1074 (Email), median rate from 1.3 to 36.8 packets per
second. A model asked to separate those is not being asked a hard question. The
single error in the held-out set is Video predicted as VoIP, which is the one
genuinely confusable pair in this data. Real traffic interleaves classes on one
tunnel, competes for bandwidth, and loses packets; none of that is in the
dataset, and all of it makes the problem harder. Treat 0.98 as evidence the
pipeline works end to end, not as an accuracy claim for deployment.

**The dataset is lab-clean.** One tunnel, one traffic class, no competing flows,
no background noise, no loss. Accuracy measured on it is an upper bound; the
field will be worse.

**Every capture in the dataset shows NAT-T.** Docker's bridge network NATs, so
IKE lands on UDP 4500 and `nat_traversal` reads true on every session. That is a
property of the harness, not of the configuration under test.

**Mid-session captures cannot report PFS.** If the capture starts after the
handshake there is no second DH exchange to observe, so `pfs_status` is
`unknown` rather than a guess. Same for any parameter the capture never
revealed: `capture_complete` goes false rather than a default being passed off
as an observation.

**IKEv2 auth method, mode and PFS are not observable.** IKE_AUTH and
CREATE_CHILD_SA are encrypted, so unless the capture was decrypted an IKEv2
tunnel reports its authentication method as undetermined, its mode
(tunnel/transport) as `unknown` and PFS as `unknown`. On the 300-capture dataset
that is every capture: cipher, integrity, DH group, IKE version and IP version
are recovered 300/300, mode, PFS and auth 0/300. Rules R06, R10 and R13 therefore
stay silent on IKEv2 — a deliberate false negative rather than a guessed
positive. IKEv1 carries mode and lifetime in Quick Mode, where they are read.

**SA lifetime is only seen on IKEv1.** IKEv2 lifetimes are local policy and never
cross the wire, so they read "not observed" and R11/R12 cannot fire on IKEv2.

**SPI-collision detection does not fire through the pipeline.** Stage 1 keys an
SA on its initiator SPI alone, so two SAs reusing one SPI across different peers
are merged before the detector sees them. The detector works on session lists
(and is tested there); the other five fire end to end.

**Nothing unobserved is scored.** A parameter the capture never revealed reads
`unknown` and triggers no rule. Where Stage 4a infers encryption or DH group
from message structure, the value is marked *inferred* everywhere it appears.

**The attack capture is synthetic.** `data/demo/attack_capture.pcap` exists to
show the anomaly detectors working with checkable evidence; it is built from
the parser's byte-level test builders, not captured from a real attack. The
detectors are threshold heuristics over one capture's sessions and have not
been measured against real attack traffic.

**Live runs are bounded.** A run re-analyses its whole capture each tick and
stops at 250,000 IPsec packets, so cost stays predictable; start a new run to
continue.

**The dataset is IKEv2 only.** The parser's IKEv1 path is covered by synthetic
fixtures, not by real captures.

## Documentation

| Document | What it covers |
|---|---|
| `SIH26160_LLD.md` | Low-Level Design — the source of truth for scope and architecture |
| `docs/VaultScope_Product_Spec.docx` | Product spec: task map, API contract, deliverables |
| `SUBMISSION.md` | The pitch: problem, what we built, the numbers |
| `DEMO_SCRIPT.md` | Timed walkthrough for the demo recording |
| `data/README.md` | The labeled dataset: matrix, naming, label schema |

Per-component notes live in the module docstrings — `testbed/harness.py`,
`core/ike_parser/`, `core/flow/` and `core/pipeline.py` each explain their own
gotchas where the code is, not in a parallel document that drifts.
