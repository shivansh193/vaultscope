# SIH26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
## Low-Level Design (LLD)

---

## 1. What we are actually building (corrected scope)

Re-reading the real PS text closely — this is **not** "monitor NTRO's live VPN mesh." It's:

1. **Build our own lab** where we can spin up IPsec VPN tunnels under many different configs (Tunnel/Transport, AES-128/256, GCM vs CBC+HMAC, different DH groups, PFS on/off, IPv4/IPv6, and different application traffic riding inside the tunnel — VoIP, WhatsApp, email, web, ICMP, video).
2. **Capture traffic** from each of those configs (IKE negotiation + ESP/AH packets + the underlying app traffic) to build a **labeled dataset** — we know ground truth because we set up the config ourselves.
3. Train/build an **AI engine** that looks at a *new* capture and predicts: IPsec protocol, IKE version, mode, encryption algo, auth algo, key exchange method, SA characteristics, and — the hard, genuinely ML-flavored part — **guess what type of traffic is inside the encrypted ESP tunnel** (VoIP vs video vs web vs email) purely from traffic metadata (packet size/timing patterns), since ESP payload itself is encrypted.
4. Layer a **rule-based security assessment** on top of what's identified (weak cipher? no PFS? bad DH group? replay protection off? long key lifetime?) → risk score, threat matrix, confidence score, executive + technical report.
5. Wrap it in a dashboard, and deliver: prototype, AI engine, dashboard, sample report, demo video, docs, and **the dataset itself** (this is an explicit deliverable — unlike your original read, they want the training data as an artifact).

So there are really **two AI problems**, of different difficulty:
- **Protocol/crypto-param identification** — mostly deterministic (IKE payloads mostly declare these in cleartext during negotiation), so this is closer to a parser + classifier hybrid, not hard ML.
- **Traffic-type-inside-ESP prediction** — genuinely hard, this is traffic analysis / side-channel classification (packet size, timing, direction, burstiness) — this is your actual "AI" showpiece.

The rest (compliance scoring, key lifetime, replay protection, forward secrecy check) is rule-based, similar to what you originally sketched — that part carries over directly.

---

## 2. Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                         STAGE 0: TESTBED (offline, one-time)           │
│  Docker/VM pairs running StrongSwan/Libreswan/OpenSwan with scripted   │
│  configs (mode × cipher × DH × PFS × IP version) + traffic generators  │
│  (VoIP/video/web/email/ICMP) piped through each tunnel                 │
└───────────────────────────┬───────────────────────────────────────────┘
                             │ produces labeled pcaps
                             ▼
┌───────────────────────────────────────────────────────────────────────┐
│  STAGE 1: CAPTURE & INGESTION                                          │
│  tshark/tcpdump wrapper → normalizes live NIC or uploaded pcap input   │
└───────────────────────────┬───────────────────────────────────────────┘
                             ▼
┌───────────────────────────────────────────────────────────────────────┐
│  STAGE 2: IKE PARSER (deterministic)                                   │
│  Reassembles IKEv1/IKEv2 handshake → extracts declared params:         │
│  version, mode, enc algo, auth algo, DH group, PFS flag, SA lifetime   │
└───────────────────────────┬───────────────────────────────────────────┘
                             ▼
┌───────────────────────────────────────────────────────────────────────┐
│  STAGE 3: ESP/AH FLOW FEATURE EXTRACTOR                                │
│  Per-flow stats on encrypted payload: packet size distribution,        │
│  inter-arrival time, direction ratio, burst patterns, flow duration    │
└───────────────────────────┬───────────────────────────────────────────┘
                             ▼
        ┌────────────────────────────────┬─────────────────────────────┐
        ▼                                ▼                             ▼
┌───────────────────┐   ┌─────────────────────────────┐   ┌─────────────────────┐
│ STAGE 4a:          │   │ STAGE 4b:                    │   │ STAGE 4c:            │
│ Protocol/Crypto    │   │ Traffic-Type Classifier (ML) │   │ Security Rule Engine │
│ Classifier         │   │ RandomForest/XGBoost/1D-CNN  │   │ (weak cipher, no PFS,│
│ (parser + light ML │   │ on flow features →           │   │ short DH, no replay  │
│ for ambiguous cases)│  │ VoIP/Video/Web/Email/ICMP    │   │ protection, etc.)    │
└─────────┬──────────┘   └───────────────┬───────────────┘   └──────────┬──────────┘
          └───────────────┬──────────────┴──────────────────────────────┘
                           ▼
          ┌───────────────────────────────────────┐
          │  STAGE 5: SCORING & REPORT AGGREGATOR   │
          │  Risk Score, Threat Matrix, AI Confidence│
          │  Score, Executive + Technical report gen │
          └───────────────────┬─────────────────────┘
                               ▼
          ┌───────────────────────────────────────┐
          │  STAGE 6: DASHBOARD / UI                │
          │  Upload pcap or select live NIC, view    │
          │  session table, drilldown, export report │
          └───────────────────────────────────────┘
```

---

## 3. Component Design

### 3.1 Testbed Generator (Stage 0)
- **Tooling:** `strongSwan` (primary — best cipher-suite flexibility via `ipsec.conf`/swanctl), Docker Compose to spin up peer pairs, `netns` (Linux network namespaces) for isolated virtual peers instead of full VMs to keep it lightweight.
- **Config matrix:** script generates configs by cartesian product of:
  `{tunnel, transport} × {AES-128, AES-256, AES-GCM, AES-CBC+HMAC-SHA256} × {MODP1024, MODP2048, ECP256} × {PFS on/off} × {IPv4, IPv6}`
- **Traffic injection per tunnel:**
  - VoIP → `sipp` or a scripted RTP generator
  - Video streaming → `ffmpeg` streaming a sample file over RTP/HTTP
  - Web browsing → `curl`/headless Chrome hitting a local nginx
  - Email → local Postfix + swaks
  - ICMP → plain `ping`
  - "WhatsApp-like" → approximate with encrypted chat-sized bursty traffic generator (can't literally run WhatsApp in an isolated lab — mention this substitution explicitly in your report to judges)
- **Output:** pcap per (config, traffic-type) combo + a metadata JSON (ground truth label) — this pcap+label pair set **is** your deliverable dataset.

### 3.2 Ingestion Engine (Stage 1)
- **Library:** `pyshark` (tshark wrapper) for structured field access; fallback to `scapy` for raw parsing flexibility.
- Accepts: uploaded `.pcap`/`.pcapng` file, or live interface name (`tshark -i <iface>`).
- Filters: `udp.port==500 or udp.port==4500` (IKE) and `esp or ah` for data-plane packets.
- Normalizes into per-session buckets keyed by `(init_SPI, resp_SPI)` for IKEv2 or `(cookie_i, cookie_r)` for IKEv1.

### 3.3 IKE Parser (Stage 2)
- Reassembles multi-message handshake per session.
- **IKEv1:** parses SA payload (transform attributes: encryption, hash, auth method, DH group, lifetime), detects Main vs Aggressive Mode from message count/pattern.
- **IKEv2:** parses SA payload proposals in `IKE_SA_INIT`, extracts ENCR/PRF/INTEG/DH transform substructures; detects `USE_TRANSPORT_MODE` notify payload to distinguish tunnel vs transport.
- **PFS detection:** presence of a second DH exchange in `CREATE_CHILD_SA` (IKEv2) or Quick Mode with KE payload (IKEv1) ⇒ PFS enabled.
- Output schema (per session):
```json
{
  "session_id": "spi_i-spi_r",
  "ike_version": "IKEv2",
  "mode": "tunnel",
  "encryption": "AES-GCM-256",
  "integrity": "implicit (AEAD)",
  "prf": "PRF_HMAC_SHA2_256",
  "dh_group": "ECP256",
  "pfs_enabled": true,
  "ip_version": "IPv6",
  "sa_lifetime_sec": 3600
}
```

### 3.4 ESP/AH Flow Feature Extractor (Stage 3)
Since ESP payload is encrypted, features must be metadata-only, per flow (grouped by SPI + 5-tuple):
- Packet size: mean, std, min/max, histogram bins
- Inter-arrival time: mean, std, jitter
- Directionality ratio (bytes up vs down)
- Burstiness (packets/sec windowed)
- Flow duration, total packet count
- Use `nfstream` or custom scapy-based flow aggregator to produce a feature vector per flow.

### 3.5 Protocol/Crypto Classifier (Stage 4a)
- Primarily **rule-based/deterministic** since IKE negotiation payloads declare these values in cleartext — a classifier here mainly handles: malformed/partial captures, vendor-proprietary extensions, or ambiguous truncated handshakes.
- Model (only where deterministic parsing fails/is ambiguous): small **Decision Tree / RandomForest** over available partial fields + packet size patterns of IKE messages (message size differs measurably by cipher suite due to payload padding).

### 3.6 Traffic-Type Classifier (Stage 4b) — the core "AI" component
- **Input:** flow feature vector from Stage 3.
- **Model choice:** start with `RandomForestClassifier` / `XGBoost` (fast, interpretable, small dataset friendly — good for hackathon timeline); stretch goal: 1D-CNN or LSTM over raw packet-size-sequence if time allows, since VoIP/video have very distinctive size/timing signatures (VoIP: small, constant-rate packets; video: large, bursty; web: bursty then idle; email: small bursts then idle; ICMP: tiny, fixed size, sparse).
- **Training data:** generated entirely from your own testbed (Stage 0) — label = traffic type injected, features = observed ESP flow stats. This is a classic "known ground truth from controlled lab" ML setup, very defensible to judges.
- **Output:** predicted class + confidence score (softmax probability) → feeds "AI Confidence Score" deliverable directly.

### 3.7 Security Rule Engine (Stage 4c)
Rule table (YAML/JSON), evaluated against Stage 2 output:

| Check | Weak condition | Reference |
|---|---|---|
| Encryption algo | DES, 3DES, AES-CBC without HMAC-256+ | NIST SP 800-77, RFC 8247 |
| DH Group | MODP768/1024 (Group 1/2) | RFC 8247 "must not use" |
| IKE version | IKEv1 Aggressive Mode | known identity-exposure weakness |
| PFS | Disabled | best practice |
| SA lifetime | > 8 hours / unusually long | operational hygiene |
| Auth method | Pre-shared key with weak DH | downgrade risk |
| Replay protection | Sequence number checking disabled | RFC 4303 |

Each rule contributes a weighted penalty → aggregated into 0–100 risk score, with **severity tags** (Critical/High/Medium/Low) feeding the Threat Matrix.

### 3.8 Scoring & Report Aggregator (Stage 5)
- Combines Stage 4a+4b+4c outputs per session into one record.
- Generates:
  - **Risk Score** (0-100, weighted rule penalties)
  - **Threat Matrix** (Likelihood × Impact grid per finding)
  - **AI Confidence Score** (from classifier softmax + parser certainty)
  - **Executive Report** (PDF, 1-page, plain-English summary, for non-technical stakeholders)
  - **Technical Report** (PDF/HTML, full parameter dump + evidence packet references)
- Use `Jinja2` templates → render to PDF via `WeasyPrint` or `reportlab`.

### 3.9 Dashboard / UI (Stage 6)
- **Frontend:** React + Tailwind, charts via Recharts.
- **Views:**
  - Upload/live-capture selector
  - Session list table (sortable, filterable by risk)
  - Session drilldown (full param breakdown, classifier confidence, applicable rule violations)
  - Aggregate dashboard (risk distribution histogram, traffic-type pie chart, threat matrix heatmap)
  - Export button → executive/technical PDF report

---

## 4. Tech Stack Summary

| Layer | Technology |
|---|---|
| Testbed / VPN peers | strongSwan, Docker Compose, Linux network namespaces |
| Traffic generation | sipp (VoIP), ffmpeg (video), curl/headless Chrome (web), Postfix+swaks (email), ping (ICMP) |
| Packet capture | tshark, tcpdump, pyshark, scapy |
| Flow feature extraction | nfstream / custom scapy aggregator |
| IKE parsing | pyshark + custom payload decoders (IKEv1/IKEv2 RFC 7296 / RFC 2409 structures) |
| ML — protocol/crypto edge cases | scikit-learn DecisionTree/RandomForest |
| ML — traffic-type classifier | scikit-learn RandomForest/XGBoost (baseline), optional PyTorch 1D-CNN (stretch) |
| Rule engine | Python, rules as YAML config |
| Report generation | Jinja2 + WeasyPrint/ReportLab |
| Backend/API | FastAPI |
| Database | SQLite (hackathon) / PostgreSQL (if scaling) |
| Frontend | React + Tailwind + Recharts |
| Containerization | Docker / Docker Compose for whole stack |

---

## 5. Data Model (core session record, persisted to DB)

```json
{
  "session_id": "string",
  "capture_source": "pcap_upload | live_nic",
  "timestamp": "ISO8601",
  "ike": {
    "version": "IKEv1 | IKEv2",
    "mode": "tunnel | transport",
    "encryption": "string",
    "auth_method": "string",
    "dh_group": "string",
    "pfs_enabled": "bool",
    "sa_lifetime_sec": "int",
    "ip_version": "IPv4 | IPv6"
  },
  "traffic_prediction": {
    "predicted_type": "VoIP | Video | Web | Email | ICMP | Other",
    "confidence": "float 0-1"
  },
  "security_assessment": {
    "risk_score": "int 0-100",
    "findings": ["string"],
    "threat_matrix_entries": [
      {"threat": "string", "likelihood": "Low|Med|High", "impact": "Low|Med|High"}
    ],
    "ai_confidence_score": "float 0-1"
  },
  "reports": {
    "executive_pdf_path": "string",
    "technical_pdf_path": "string"
  }
}
```

---

## 6. Suggested Team Split (5-6 people)

1. **Testbed & dataset generation** (strongSwan configs + traffic generators + pcap/label export) — most infra-heavy, start Day 1.
2. **IKE parser** (Stage 2 — deterministic parsing, both IKE versions).
3. **Flow feature extraction + ML traffic-type classifier** (Stages 3-4b) — the core AI component, needs Stage 1's dataset early.
4. **Security rule engine + report generation** (Stage 4c + 5).
5. **Backend API + DB integration** (glues 2-5 together).
6. **Frontend dashboard** (Stage 6) — can start on mocked JSON before backend is ready.

## 7. Key Risks / Things to flag to judges proactively
- "WhatsApp" traffic can't be literally reproduced in an isolated lab (it needs live Meta servers) — substitute with a traffic generator that mimics its packet-size/timing signature and disclose this explicitly.
- ESP/AH traffic-type prediction is a side-channel inference problem — accuracy will not be 100%, report it honestly with a confusion matrix rather than overclaiming.
- Dataset generated is inherently lab-controlled (clean network, no cross-traffic noise) — real-world accuracy will likely be lower; mention as a documented limitation, not hidden.
