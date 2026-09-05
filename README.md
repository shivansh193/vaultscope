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

## Commit convention

One commit per task ID from spec Section 9, e.g.
`feat(ike_parser): IKEv2 SA_INIT + IKE_AUTH full VPNSession extraction`.
Every task ships with its mandatory test passing before merge.
