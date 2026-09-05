# CLAUDE.md — VaultScope

Guidance for AI agents / future sessions working in this repo. Keep it current:
**when you change something structural, update this file and the nearest
subtree `CLAUDE.md` in the same commit.**

## What this is

VaultScope — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment
Framework (SIH 2026 · SIH26160 · NTRO). Passive-first: pcap in → per-session
IKE crypto reconstruction → CVE-linked risk scoring → ESP traffic-type ML →
layered reports. Full spec: `docs/VaultScope_Product_Spec.docx` (Section
numbers referenced throughout the code are from that document).

## Team / ownership (2 engineers)

| Block | Owner | Slices | Directories |
|---|---|---|---|
| **A** | @shivansh193 | P1 + P2 | `testbed/`, `core/ingestion/`, `core/ike_parser/`, `core/flow/`, `core/classifiers/`, `data/`, `models/` |
| **B** | @p4ralyn | P3 + P4 | `core/rules/`, `reporting/`, `api/`, `frontend/` |

Blocks develop async against the shared data model (spec §5) and API contract
(spec §11). Don't edit the other block's directories without coordinating.

## Working agreement

- **One PR per task ID** from spec §9 (`P2-T1`, `P2-T2`, …). Branch name
  `feat/<taskid>-<slug>`. Commit subject `feat(<area>): <what>` matching the
  spec's commit-map line. Every task ships with its mandatory test passing.
- **Stacked PRs**: a task that builds on an unmerged task branches off that
  branch, not `main`. Rebase onto `main` once the parent merges.
- Do **not** add `Co-Authored-By: Claude` trailers to commits.
- Run before every commit: `.venv/Scripts/python -m pytest -q` and
  `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m ruff format --check .`
- Env: Python 3.11 venv at `.venv/`. `pyproject.toml` sets `pythonpath=["."]`
  so `import core.<pkg>` works with no install.

## Subtree guides

- `core/ike_parser/CLAUDE.md` — Stage 2 IKE parser design, wire-format notes,
  VPNSession schema contract, task status.

## Change log (newest first)

- **P2-T2** `feat/p2-t2-ikev1-parser` (stacked on P2-T1) — IKEv1 / ISAKMP
  parser: `parse_ikev1()`, Main vs Aggressive Mode detection (ID-payload-in-
  message-1 signal), phase-1 crypto extraction. Added `core/ike_parser/ikev1.py`,
  `V1_*` constants + `canon_v1_*` in `_transforms.py`, IKEv1 encrypted-message
  handling in `_wire.py`, `_read_pcap`/`_normalise` in `ikev2.py` made
  version-agnostic (callers filter). Tests: `tests/ike_parser/test_ikev1_parser.py`.
- **P2-T1** `feat/p2-t1-ikev2-parser` (PR #2) — IKEv2 parser: `parse_ikev2()`,
  SA_INIT + IKE_AUTH → `VPNSession`. New package modules `_transforms.py`,
  `_wire.py`, `models.py`, `ikev2.py`. Tests: `tests/ike_parser/test_ikev2_parser.py`,
  synthetic RFC 7296 fixtures in `tests/ike_parser/_build.py`.
- **Env setup** (`main`) — repo skeleton per spec §3.2, Python tooling,
  `requirements*.txt`, `pyproject.toml`, smoke tests.
