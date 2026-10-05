# VaultScope — SIH 2026 Submission

**AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework**
Problem Statement **SIH26160** · **NTRO** (National Technical Research Organisation)

---

## 1. The problem

NTRO runs large IPsec VPN infrastructure across sensitive government networks. An
IPsec tunnel is only as strong as the cryptographic parameters the two peers
negotiate on the wire — and in practice those deployments accumulate years of
**configuration drift**. IKEv1 with DES and 1024-bit Diffie-Hellman sits next to
modern IKEv2. Administrators have **no continuous visibility** into what is
actually being negotiated versus what the config file claims.

The PS asks for an **AI-powered** tool that:

- identifies the protocol and cryptographic parameters of every VPN session,
- **classifies the application traffic running inside the encrypted tunnel**
  (VoIP / video / web / email / ICMP / chat) purely from encrypted-traffic
  metadata,
- scores each session for security weaknesses against CVEs and standards,
- and produces a labeled dataset, a working prototype, and layered reports.

---

## 2. What VaultScope is

A **passive-first** IPsec security intelligence platform. Feed it a `.pcap`,
point it at a live NIC, or replay a stored capture, and it:

1. **reconstructs the full IKE negotiation state** of every VPN session
   (IKEv1 Main / Aggressive / Quick Mode **and** IKEv2, from the raw bytes),
2. **infers the traffic type inside each ESP tunnel** with a trained ML model,
   using only packet size / timing / direction — the payload is encrypted,
3. **scores every session** against a 21-rule CVE-linked engine and detects
   **runtime attacks** (downgrade, proposal enumeration, PSK-hash harvesting,
   rekey storms, unexpected NAT-T) that static config review cannot
   see — each citing the **exact pcap frame numbers**, with the capture itself
   downloadable so anyone can verify it in Wireshark,
4. **produces** an executive PDF, a technical HTML report with per-finding CVE
   links and vendor-specific config diffs, SIEM-ready JSON/CEF, and a React
   dashboard with a risk-coloured peer graph,
5. every finding links to a **specific RFC, CVE, or NIST standard** — nothing is
   a black box.

It is **not** a scanner (`ike-scan`), **not** a config linter (Tufin/AlgoSec),
and **not** a manual decode tool (Wireshark). It is a continuous assessment
platform that combines all three plus the ML layer.

---

## 3. What we built — the pipeline

Data flows Stage 0 → 6. Stages 4a/4b/4c run in parallel off the parsed session,
then converge at Stage 5.

| Stage | Component | What it does |
|---|---|---|
| **0** | `testbed/` | strongSwan peer pairs in Docker over a Cartesian config matrix (cipher × integrity × DH group × PFS × IP version × 6 traffic classes); traffic generators (sipp/RTP, ffmpeg, curl, swaks, hping3, a bursty-chat generator); capture script → labeled pcap + ground-truth JSON. **The dataset is itself a PS deliverable.** |
| **1** | `core/capture.py`, `core/ingestion/` | **One** read of the pcap (`core/capture.py`) yields every IKE message and ESP/AH packet with its frame number, timestamp, peers and port; Stage 1 buckets them into SAs by `(SPI_i, SPI_r)` / `(cookie_i, cookie_r)` and hands each SA its own ESP. Stages 2 and 3 consume the same read. Flags NAT-T, fragmented IKE, mid-session captures. |
| **2** | `core/ike_parser/` | **Hand-rolled RFC 7296 / RFC 2408 byte-level decoder** (no dependency on Wireshark for the logic). Recovers encryption, integrity, PRF, DH group, PFS status, auth method, SA lifetime, vendor, DPD, retransmission timing, and peer-certificate facts. Detects IKEv1 Aggressive Mode by **ID-payload-in-message-1**, not message count (retransmissions break count-based detection). |
| **3** | `core/flow/` | 13-feature metadata vector per ESP flow: packet-size mean/std/percentiles, inter-arrival timing, direction ratio, and a burst model (`burst_count`, `burst_gap_ratio`, `payload_size_var_burst`) built to separate Video from Web. |
| **4a** | `core/classifiers/` | RandomForest fallback that recovers encryption + DH group from IKE **message structure** when the parser can't — the KE payload length is a near-perfect fingerprint of the DH group. Fills **only** fields the parser left `unknown`, only above 0.6 confidence, and every such value is marked *inferred* in the console and reports. |
| **4b** | `core/classifiers/` | **The AI showpiece.** RandomForest + XGBoost over the Stage 3 vector; auto-selects the better model by macro-F1. Ships a trained model plus `confusion_matrix.json`, per-class precision/recall/F1, and a feature-importance chart. |
| **4c** | `core/rules/` | 21 rules as **data** (`rules.yaml`), four operators, evaluated against `ike.*`. Weighted penalty → 0–100 risk score; any CRITICAL rule forces overall severity. |
| **5** | `reporting/` | Jinja2 → WeasyPrint. Executive PDF (1 page, plain English, top 3). Technical HTML (full session table, CVE/RFC links, vendor config diffs, the confusion matrix). JSON + escaped CEF export (one event per finding + a `VS-CLEAN` event per healthy tunnel so SIEM never loses a session). |
| **6** | `frontend/` | Next.js / Tailwind / D3 / Recharts. Upload, capture history, session table (sortable, CRITICAL rows red, attacked sessions flagged), **D3 force-directed peer graph** coloured by worst-session risk, session drilldown with attack indicators and evidence frames, aggregate charts, **live capture** (interface or replay) over WebSocket, two-pcap historical diff, export panel. Responsive down to phone width. |

Glue: `core/pipeline.py` is the **Analysis module** — `analyze_capture(path)`
returns every session parsed, classified and scored, plus the anomalies and
capture statistics, from one read of the file. `api/` is FastAPI + SQLite with
auto-generated Swagger: every analysed capture is a **job** with a summary
(severity mix, posture, anomaly count) that every view of the console shares.
`core/live.py` puts live capture behind one seam with two adapters — `dumpcap`
on a real NIC, and replay of a stored capture — both feeding the same Analysis
module.

---

## 4. The moat — why this beats every existing tool

| Tool | Gap VaultScope fills |
|---|---|
| `ike-scan` / `ikeforce` / `iker.py` | Active-only, no passive mode, no established-session analysis, no ESP, unmaintained (last commit 2012 / Python 2) |
| Wireshark | Manual expert tool: no automation, scoring, remediation, or ML |
| Tufin / AlgoSec | Analyse **config files**, zero visibility into runtime cipher negotiation |
| Cisco Stealthwatch / Nessus | See that IPsec exists; do not decode IKE at cipher level |

**VaultScope is the first tool combining:** passive capture → full IKE decode →
**traffic-type ML on encrypted flows** → CVE-linked scoring → vendor-specific
config diffs → SIEM export → risk-propagating peer graph.

---

## 5. The numbers

- **~5,700 lines** of pipeline/API Python, **16** React components across
  **7** console views.
- **380** Python tests (parser, capture reader, ingestion, flow, classifiers,
  rules, anomalies, Analysis module, reports, API, jobs, live capture, the
  Docker testbed), **57** vitest unit/component tests, **23** Cypress
  end-to-end tests against the real stack. CI runs all three on every push.
- **21** security rules, each tied to a CVE / RFC / NIST reference, mapped onto **6** compliance baselines.
- Traffic classifier: **macro-F1 0.98** on a held-out split of the 300-capture
  strongSwan dataset (up from 0.79 on the synthetic bootstrap it replaced). Read
  it as proof the pipeline works end to end, **not** as a field accuracy — see §8.
- **5** runtime attack detectors firing end to end (a sixth, SPI collision,
  works on session lists only — see §8), each producing an `AnomalyEvent` with
  **exact pcap frame numbers** as evidence; `data/demo/attack_capture.pcap`
  trips all five.
- Protocol identification on the 300 labeled captures: cipher, integrity, DH
  group, IKE version, IP version **300/300**; mode, PFS and peer auth are inside
  the encrypted IKE_AUTH and read `unknown` rather than a guess.

---

## 6. The 5-minute demo script

> One command: `docker compose up`. Everything below is in the browser.
> The full timed script is `DEMO_SCRIPT.md`.

1. **Upload** `data/demo/demo_capture.pcap` — six real strongSwan tunnels, weak
   through strong. → the session table, CRITICAL rows in red.
2. **Peer graph.** D3 force-directed. A node is a VPN peer; colour = its worst
   session's risk. Click the red node → the table filters to that peer.
3. **Session drilldown.** Click a CRITICAL session: full IKE decode (DES-CBC,
   **MODP1024**), triggered rules with references (**R04 → LOGJAM**), the
   **traffic-type prediction** with the model version stamped on it, and the
   exact **vendor config diff** that fixes it.
4. **Attack with evidence.** Upload `data/demo/attack_capture.pcap`. Five kinds
   of attack indicator appear — Aggressive Mode probing, proposal enumeration,
   downgrade, NAT-T from a public peer, a rekey storm — each saying *"frames
   9, 10"*. Click **Download the capture**, open it in Wireshark, Go to Packet 9.
   Judges can check it themselves.
5. **Live.** On the Live page, replay the demo capture at 50×: sessions stream
   into the table as the backend finds them, and the run is saved as its own job.
   The same button captures from a real NIC when the host allows it.
6. **Reports + diff.** Executive PDF (plain English, top 3, signs of attack),
   technical HTML (inventory, CVE links, anomalies with frames, the confusion
   matrix), JSON/CEF straight into a SIEM. Compare two captures: new peers,
   gone peers, degraded scores.

---

## 7. The interesting bits — bring these up in Q&A

- **We built our own IKE decoder from the RFC bytes.** Pure `struct`, ~350
  lines, IKEv1 *and* IKEv2. It reads key-logged / tshark-decrypted captures for
  the encrypted parts (IKE_AUTH SK, IKEv1 Quick Mode) and degrades cleanly to
  "unknown" when it can't — it never guesses a value that a rule would penalise.
- **Aggressive Mode detection is a correctness fix, not a feature.** We detect
  it by the **presence of an ID payload in message 1**, because message *count*
  is corrupted by retransmissions. The retransmission *interval* itself is a
  secondary vendor fingerprint (Cisco ~10 s, strongSwan ~3 s).
- **The KE payload length fingerprints the DH group.** MODP2048 → 256 bytes,
  ECP256 → 64 bytes. Our Stage 4a classifier recovers the DH group from a
  *truncated* handshake using nothing but message structure.
- **Downgrade detection is runtime, not static.** If one peer pair negotiates
  both a strong suite and a weak one, that is proposal-stripping by an on-path
  attacker — not a config mistake. Most teams only do static analysis.
- **PFS = "unknown" is a first-class state.** A mid-session capture that never
  saw a CHILD_SA negotiation must not be scored as "PFS disabled" — that would
  be a false CRITICAL. Rule R10 fires only on a *proven* "disabled".
- **The ML is reported honestly.** Confusion matrix in the technical report,
  per-class F1, and an explicit "lab-clean training data; real-world accuracy
  will be lower" disclosure. The **Chat class is a disclosed substitute** —
  real WhatsApp can't run in an isolated lab, so it's approximated with a
  bursty chat-sized generator, and that is stated in the dataset spec, the
  report, and here.
- **Every finding has a citation.** RFC 8247, RFC 9395, CVE-2016-1287
  (fragmented IKE on Cisco ASA), CVE-2016-2183 (SWEET32), LOGJAM, SLOTH,
  NIST SP 800-77, CNSSP-15.
- **Peer certificates get analysed.** When auth is RSA, we parse the X.509 CERT
  payload — expiry, key size, signature algorithm, self-signed — and an expired
  cert is an automatic CRITICAL (rule R16). One payload, a whole class of
  findings, zero extra rules.

---

## 8. Honest limitations (say these before a judge asks)

- The labeled dataset is **lab-clean** — one tunnel, one traffic class, no
  cross-traffic, no loss — so the 0.98 macro-F1 is an upper bound. Real
  networks will score lower, and Video vs Web is genuinely hard.
- The **Chat class is a disclosed substitute**: a scripted bursty generator,
  not real messenger traffic.
- **IKEv2 mode, PFS and authentication are encrypted** (IKE_AUTH), so they read
  *unknown* unless the capture was decrypted; tunnel/transport is the one
  requirement of the PS we identify only on IKEv1 or decrypted IKEv2. SA
  lifetime is never sent in IKEv2. SPI-collision detection does not fire
  through the pipeline (SAs are keyed on initiator SPI).
- Dependent rules (R06, R10, R13) then stay silent rather
  than guess.
- `data/demo/attack_capture.pcap` is **synthetic** — built from the parser's
  byte-level test builders to demonstrate the detectors with checkable evidence.
  The detectors are threshold heuristics, not measured on real attack traffic.
- Active mode (sending IKE probes to discover peers) is **not built**;
  VaultScope is a passive assessment platform. Live capture needs capture
  privilege on the host.

---

## 9. Deliverables checklist

| # | Deliverable | Status |
|---|---|---|
| 1 | Labeled dataset (pcaps + JSONs) | ✅ 300 captures, all six classes; labels in `data/labels/`, corpus regenerated with `scripts/generate_dataset.py` |
| 2 | Trained AI model artifacts (`model.pkl` + `eval_metrics.json` + `confusion_matrix.json`) | ✅ trained on the captured dataset (`source: pcap-dataset`) |
| 3 | Working prototype (`docker compose up`) | ✅ |
| 4 | Executive PDF report | ✅ |
| 5 | Technical HTML report | ✅ |
| 6 | JSON / CEF export | ✅ (anomalies included) |
| 7 | Dashboard (peer graph, drilldown, anomalies, live capture, exports) | ✅ |
| 8 | Demo video (3–5 min) | ✅ <VIDEO-URL-PLACEHOLDER> (script: `DEMO_SCRIPT.md`) |
| 9 | This document + product spec | ✅ (`docs/`, `SIH26160_LLD.md`) |
| 10 | API reference (Swagger `/docs`) | ✅ |
| 11 | Setup guide (`README.md`) | ✅ |
| 12 | Disclosed limitations section | ✅ (§8, `README.md`, technical report) |
