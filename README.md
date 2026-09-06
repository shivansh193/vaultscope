# VaultScope

**AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework**
SIH 2026 · Problem Statement SIH26160 · NTRO

VaultScope is a passive-first, active-capable IPsec VPN security intelligence
platform: it ingests traffic at the packet level, reconstructs the cryptographic
negotiation state of every VPN session, scores each session against a
CVE-linked rule database, classifies the traffic type running inside each
encrypted tunnel, and produces layered reports with vendor-specific remediation.

Full design: [`docs/VaultScope_Product_Spec.docx`](docs/VaultScope_Product_Spec.docx).

---

## Team

Two engineers. The spec's four slices (P1–P4, Section 8) are grouped into two
ownership blocks:

| Block | Owner | Slices | Scope |
|---|---|---|---|
| **A** | [@shivansh193](https://github.com/shivansh193) | P1 + P2 | Stages 0–4b: testbed, dataset, ingestion, IKE parser, flow features, ML classifiers |
| **B** | [@p4ralyn](https://github.com/p4ralyn) | P3 + P4 | Stages 4c–6: rule engine, scoring, reports, FastAPI backend, DB, React dashboard, Docker Compose, demo video |

## Repository layout

| Path | Stage | Owner |
|---|---|---|
| `testbed/` | Stage 0 — testbed & dataset generator | A |
| `core/ingestion/` | Stage 1 — ingestion engine | A |
| `core/ike_parser/` | Stage 2 — IKEv1/v2 parser | A |
| `core/flow/` | Stage 3 — ESP flow feature extractor | A |
| `core/classifiers/` | Stage 4a/4b — protocol + traffic-type ML | A |
| `core/rules/` | Stage 4c — security rule engine | B |
| `reporting/` | Stage 5 — scoring + report aggregator | B |
| `api/` | FastAPI backend + WebSocket | B |
| `frontend/` | Stage 6 — React dashboard | B |
| `data/` | dataset: pcaps + ground-truth JSONs | A |
| `models/` | trained model artifacts + eval metrics | A |
| `tests/` | mirrors the slices above; run with `pytest` | both |
| `docs/` | product spec + API reference + setup guide | both |

Blocks are developed async against the shared data model (spec Section 5) and
API contract (spec Section 11). `data/mock/` holds fixture JSON so Block B can
build the UI before the backend is live.

## Prerequisites

- Python **3.11**
- `tshark` / Wireshark on `PATH` (runtime dependency of `pyshark`)
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
| `tshark` | `pyshark`, Stage 1 ingestion | macOS `brew install wireshark` · Debian/Ubuntu `apt install tshark` · Windows: install Wireshark, add to PATH |
| pango / glib | `weasyprint`, Stage 5 reports | macOS `brew install pango libffi` · Debian/Ubuntu `apt install libpango-1.0-0 libpangoft2-1.0-0` · Windows: GTK runtime |

> **macOS (Apple Silicon):** `brew install pango libffi` is enough — importing
> `reporting` first fixes the library lookup in-process (`ctypes.util.find_library`
> does not search `/opt/homebrew/lib`). Always `import reporting` before
> `import weasyprint`; no shell export needed.

> On Windows, `weasyprint` (Stage 5, Block B) needs the GTK runtime. Block A
> work does not require it; install the Block A subset if the full install fails on your box:
> `pip install scapy pyshark scikit-learn xgboost numpy pandas matplotlib joblib pyyaml pytest pytest-cov`

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

## Running tests

```bash
pytest                 # whole suite from repo root
pytest tests/ike_parser # one slice
pytest -m "not slow"   # skip tests needing the full dataset / trained model

ruff check . && ruff format --check .
```

`tests/test_environment.py` is the environment smoke test: it asserts the
directory skeleton, the importable dependency set, `tshark` on `PATH`, an
end-to-end `scapy` → `pyshark` pcap round-trip, and `weasyprint` PDF rendering.
Run it first on a new box.

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
| 8 | Demo video (3-5 min) | All | Not started |
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

**IKEv2 auth method is not observable.** IKE_AUTH is encrypted, so a PSK tunnel
currently reports the model default rather than `None`. Tracked as a P2-T4 gap
in the parser's module docstrings; rules R06 and R13 depend on it.

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
