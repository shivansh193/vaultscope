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

A **passive-first** IPsec security intelligence platform. Feed it a `.pcap`
(or a live NIC) and it:

1. **reconstructs the full IKE negotiation state** of every VPN session
   (IKEv1 Main / Aggressive / Quick Mode **and** IKEv2, from the raw bytes),
2. **infers the traffic type inside each ESP tunnel** with a trained ML model,
   using only packet size / timing / direction — the payload is encrypted,
3. **scores every session** against an 18-rule CVE-linked engine and detects
   **runtime attacks** (downgrade, proposal enumeration, PSK-hash harvesting,
   SPI replay) that static config review cannot see,
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
| **1** | `core/ingestion/` | One pcap read → per-session IKE + ESP streams bucketed by `(SPI_i, SPI_r)` (IKEv2) / `(cookie_i, cookie_r)` (IKEv1). pyshark primary, scapy fallback. Flags NAT-T, fragmented IKE, mid-session captures. |
| **2** | `core/ike_parser/` | **Hand-rolled RFC 7296 / RFC 2408 byte-level decoder** (no dependency on Wireshark for the logic). Recovers encryption, integrity, PRF, DH group, PFS status, auth method, SA lifetime, vendor, DPD, retransmission timing, and peer-certificate facts. Detects IKEv1 Aggressive Mode by **ID-payload-in-message-1**, not message count (retransmissions break count-based detection). |
| **3** | `core/flow/` | 13-feature metadata vector per ESP flow: packet-size mean/std/percentiles, inter-arrival timing, direction ratio, and a burst model (`burst_count`, `burst_gap_ratio`, `payload_size_var_burst`) built to separate Video from Web. |
| **4a** | `core/classifiers/` | RandomForest fallback that recovers encryption + DH group from IKE **message structure** when the parser can't — the KE payload length is a near-perfect fingerprint of the DH group even in a truncated capture. |
| **4b** | `core/classifiers/` | **The AI showpiece.** RandomForest + XGBoost over the Stage 3 vector; auto-selects the better model by macro-F1. Ships a trained model plus `confusion_matrix.json`, per-class precision/recall/F1, and a feature-importance chart. |
| **4c** | `core/rules/` | 18 rules as **data** (`rules.yaml`), four operators, evaluated against `ike.*`. Weighted penalty → 0–100 risk score; any CRITICAL rule forces overall severity. |
| **5** | `reporting/` | Jinja2 → WeasyPrint. Executive PDF (1 page, plain English, top 3). Technical HTML (full session table, CVE/RFC links, vendor config diffs, the confusion matrix). JSON + escaped CEF export (one event per finding + a `VS-CLEAN` event per healthy tunnel so SIEM never loses a session). |
| **6** | `frontend/` | Next.js / Tailwind / D3 / Recharts. Upload, session table (sortable, CRITICAL rows red), **D3 force-directed peer graph** coloured by worst-session risk, session drilldown, aggregate charts, live WebSocket stream, two-pcap historical diff, export panel. |

Glue: `core/pipeline.py` runs the whole chain and **degrades gracefully** —
every stage is probed independently, so a capture benefits from each component
the moment it exists. `api/` is FastAPI + SQLite with auto-generated Swagger.

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

- **~4,600 lines** of pipeline Python + **21** React components.
- **~250** Python tests passing (parser, flow, classifiers, rules, reports, API,
  ingestion, anomalies) — every RFC structure exercised against the real decoder.
- **18** security rules, each tied to a CVE / RFC / NIST reference.
- Traffic classifier: **macro-F1 ≈ 0.79** on the bootstrap set — honestly below
  a fake 1.0, with the spec-predicted confusion pattern (VoIP/ICMP easy,
  **Video↔Web the hard pair**). Retrains on the real strongSwan dataset with
  one command.
- **6** protocol-level attack detectors, each producing an `AnomalyEvent` with
  **exact pcap frame numbers** as evidence.

---

## 6. The 5-minute demo script

> One command: `docker compose up`. Everything below is in the browser.

1. **Upload** a demo `.pcap` (mixed IKEv1 + IKEv2, a couple of weak tunnels).
   → redirects to the session table, CRITICAL rows in red.
2. **Peer graph.** D3 force-directed. A node is a VPN peer; colour = its worst
   session's risk; label = the **fingerprinted vendor** ("Cisco ASA",
   "strongSwan"). Click the red node → the table filters to that peer.
   *This is the single most visual moment — lead with it.*
3. **Session drilldown.** Click a CRITICAL session:
   - full IKE decode (version, mode, AES-128-CBC, **MODP1024**, PFS disabled),
   - triggered rules with CVE links (**R04 → LOGJAM**, **R10 → PFS off**),
   - the **traffic-type prediction** ("Video, 0.83 confidence") with the model
     version stamped on it,
   - the exact **vendor config diff** to fix it, in a monospace block.
4. **Anomaly with evidence.** Point at a `DOWNGRADE_SUSPECTED` or
   `AGGRESSIVE_MODE_PROBE` event: *"detected at packet #47, 14:32:01.443 —
   open Wireshark and verify."* Judges can check it.
5. **Reports.** Download the executive PDF (plain-English, top 3, one page) and
   the technical HTML (session inventory, CVE links, **the confusion matrix**,
   vendor diffs). Show the JSON/CEF export dropping straight into a SIEM.
6. **Live mode + historical diff** (30 s each): new sessions appear in the table
   within 2 s over WebSocket; load two pcaps and diff them — new peers, degraded
   scores, changed cipher suites. *No other tool does the diff.*

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

- The labeled dataset is **lab-clean** — no cross-traffic noise — so real-world
  classifier accuracy will be lower than the reported metrics.
- The shipped models are trained on a **synthetic bootstrap** set with realistic
  per-class noise and class contamination; `python -m core.classifiers.train`
  swaps in models trained on the captured strongSwan dataset.
- Traffic-type inference is **side-channel** — it will never be 100%, and Video
  vs Web is genuinely hard. We report that, we don't hide it.
- Active mode (sending IKE probes to discover peers) is **secondary** and
  minimal; VaultScope is a passive assessment platform first.

---

## 9. Deliverables checklist

| # | Deliverable | Status |
|---|---|---|
| 1 | Labeled dataset (pcaps + JSONs) | Testbed + generator complete; run on a Linux/Docker host to produce the corpus |
| 2 | Trained AI model artifacts (`model.pkl` + `eval_metrics.json` + `confusion_matrix.json`) | ✅ shipped (bootstrap; retrain on dataset) |
| 3 | Working prototype (`docker compose up`) | ✅ |
| 4 | Executive PDF report | ✅ |
| 5 | Technical HTML report | ✅ |
| 6 | JSON / CEF export | ✅ |
| 7 | Dashboard (peer graph, drilldown, exports) | ✅ |
| 8 | Demo video (3–5 min) | Script in §6 |
| 9 | This document + product spec | ✅ (`docs/`, `SIH26160_LLD.md`) |
| 10 | API reference (Swagger `/docs`) | ✅ |
| 11 | Setup guide (`README.md`) | ✅ |
| 12 | Disclosed limitations section | ✅ (§8, testbed docs, technical report) |
