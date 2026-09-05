# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Maintaining this file

After every `git push`, review whether this file is still accurate and update it — new build/lint/test/run commands, changed architecture, new stages implemented, or stack decisions that diverged from the LLD. Keep the "Project status", "Commands", and "Tech stack" sections in sync with what actually exists in the repo.

## Project status

**Scaffolded, no pipeline code yet.** The repo has its Python environment, package skeleton, test tree, and lint/test config in place; every pipeline slice (`core/*`, `reporting/`, `api/`, `testbed/`, `frontend/`) is an empty package awaiting implementation. The only substantive design artifacts are `SIH26160_LLD.md` (Low-Level Design, SIH 2026 PS SIH26160) and `docs/VaultScope_Product_Spec.docx`. Read the LLD first; it is the single source of truth for scope and architecture, and its section numbering is a useful shared vocabulary (e.g. "Stage 4b", "Section 3.6").

Work is split across four async slices (P1–P4), grouped into two engineer blocks: Block A (@shivansh193) owns P1+P2 (Stages 0–4b), Block B (@p4ralyn) owns P3+P4 (Stages 4c–6). `README.md` maps each directory to its stage and owner.

## Commands

```bash
# setup (Python 3.11; see README for tshark / pango system deps)
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

pytest                      # whole suite from repo root
pytest tests/ike_parser     # one slice
pytest -m "not slow"        # skip tests needing the full dataset / trained model
ruff check . && ruff format --check .
```

`pyproject.toml` sets `pythonpath = ["."]`, so `import core.ike_parser` works with no install step. `tests/test_environment.py` is the environment smoke test — it asserts the directory skeleton, the importable dependency set, and `tshark` on PATH. Keep its skeleton list current when directories are added.

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

The persisted per-session record (LLD Section 5) is the contract that glues stages together — the IKE parser, classifiers, rule engine, DB, API, and frontend all agree on this shape. Match its field names and nesting (`ike`, `traffic_prediction`, `security_assessment`, `reports`) rather than inventing new ones. The rule engine's checks (weak cipher, MODP768/1024, IKEv1 Aggressive Mode, PFS off, long SA lifetime, replay protection off) map directly onto `ike.*` fields and are defined as data (YAML/JSON), not hardcoded logic.

## Tech stack

Backend FastAPI; DB SQLite (hackathon) / PostgreSQL (scale); ML scikit-learn (RandomForest/XGBoost baseline, optional PyTorch 1D-CNN stretch); reports Jinja2 + WeasyPrint/ReportLab; frontend React/Tailwind/Recharts; whole stack containerized via Docker Compose.

Python deps are pinned across three manifests: `requirements.txt` (runtime), `requirements-dev.txt` (adds pytest/ruff/httpx), and `requirements-stretch.txt` (`torch`, `nfstream` — install only when working that stretch goal; `nfstream` is an accelerator, the custom scapy aggregator is the primary Stage 3 path). `requirements.lock.txt` is a known-good `pip freeze` to fall back on if resolution conflicts. The frontend and DB layers have no manifest yet.

## Working principles specific to this project (from the LLD's own callouts)

- **Report ML honestly.** ESP traffic-type prediction is side-channel inference; accuracy will not be 100%. Produce a confusion matrix rather than overclaiming.
- **The "WhatsApp" class is a substitution** — it can't run in an isolated lab, so it's approximated with a bursty chat-sized generator. Keep this labeled as such; don't present it as real WhatsApp traffic.
- **The dataset is lab-clean** (no cross-traffic noise), so real-world accuracy will be lower — treat this as a documented limitation, not something to hide.
