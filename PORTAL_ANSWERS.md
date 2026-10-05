# SIH26160 portal submission (paste-ready)

Form limits: Idea Title 100 chars, Idea Description 50,000, Abstract/Summary 10,000. Template upload must be a PDF (convert the filled SIH2026 PPTX). Facts below were checked against the repo on 2026-10-05 (380 pytest tests, 57 vitest, 23 Cypress, 21 rules, 300 labeled captures, macro-F1 0.9801 on n_test=45).

## Technology Bucket

Blockchain & Cybersecurity (as listed on the problem statement).

## Idea Title (max 100)

```
VaultScope: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
```

## Abstract / Summary (max 10,000)

```
VaultScope turns a raw IPsec capture into an interpretable security verdict, with no manual packet inspection. It treats two different questions as two different problems.

1) What cryptography is this tunnel using? This is not machine learning. IKE negotiates in cleartext, so a from-scratch RFC 7296 / RFC 2408 byte-level decoder reads IKE version, cipher, integrity, PRF, Diffie-Hellman group, SA lifetime and vendor fingerprint directly from the capture. ML is reserved for ambiguous or truncated handshakes.

2) What is travelling inside the encrypted ESP tunnel? This is the genuine ML problem. The payload is ciphertext, so a RandomForest/XGBoost classifier predicts VoIP, Video, Web, Email, Chat or ICMP from metadata side-channels only: packet-size distribution, inter-arrival timing, direction ratio and burstiness. Every prediction carries a confidence score and the features that drove it, and low-confidence flows abstain instead of guessing.

Around these two engines the platform provides: a data-driven security rule engine (21 YAML rules, each tied to a CVE, RFC or NIST reference) covering cryptographic strength, cipher suite, DH group, key lifetime, replay protection and Perfect Forward Secrecy; compliance mapping to NIST SP 800-77r1/800-131A, BSI TR-02102-3, CNSA 2.0, CERT-In and TEC ITSAR; a metadata-exposure score describing what an observer learns without any keys; post-quantum readiness detection (RFC 9370 / ML-KEM); runtime attack detection with exact pcap frame numbers as evidence (aggressive-mode probing, transform brute force, downgrade, NAT-T misuse, rekey storms); optional import of gateway state (swanctl, ip xfrm) to fill the fields the wire hides; and a hash-chained tamper-evident audit log.

Outputs: a 0-100 risk score, threat matrix, AI confidence score, executive PDF report, technical report with vendor-specific remediation, JSON/CEF export, and an interactive dashboard with live capture and replay.

The training data is a deliverable of its own: 300 labeled captures from real strongSwan tunnels in Docker across tunnel/transport, AES-128/256, AES-GCM, AES-CBC+HMAC, 3DES/DES, MODP1024/2048/ECP256, PFS on/off and IPv4/IPv6 (136 distinct configurations), carrying six traffic classes. We report results honestly: macro-F1 0.98 is an upper bound because each lab capture holds one traffic class and no cross-traffic, and fields that are encrypted in IKE_AUTH are reported "unknown" or "inferred" rather than guessed.
```

## Idea Description (max 50,000)

```
1. PROBLEM UNDERSTANDING

IPsec protects enterprise, government, military and cloud links, but its security depends on choices that are easy to get wrong: cipher, integrity algorithm, DH group, authentication, PFS, SA lifetime, anti-replay, and tunnel vs transport mode. Wireshark gives packet-level visibility but needs an expert to interpret it. NTRO's problem is to let an analyst understand the security posture of an IPsec deployment from a capture or live stream without reading packets.

The statement hides two problems of very different difficulty, and VaultScope keeps them separate:
- Identifying the protocol and crypto is mostly deterministic, because IKE declares its proposal in cleartext. It needs a correct parser, not a model.
- Predicting the traffic type inside ESP is a real ML problem, because the payload is encrypted and only metadata (sizes, timing, direction, bursts) leaks.

2. PROPOSED SOLUTION

VaultScope is a staged pipeline:
Capture/PCAP -> ingestion -> IKE parser -> flow features -> classifiers + rule engine (parallel) -> scoring and reports -> dashboard.

Stage 0, testbed: real strongSwan peers in Docker Compose over the configuration matrix from the brief (tunnel/transport, AES-128, AES-256, AES-GCM, AES-CBC+HMAC, 3DES/DES for weak-crypto coverage, MODP1024/MODP2048/ECP256, PFS on/off, IPv4/IPv6), with six traffic generators riding each tunnel (sipp/RTP VoIP, ffmpeg video, curl web, swaks SMTP email, ICMP, and a bursty chat generator that stands in for a messaging client). Each capture is stored with a ground-truth JSON label.
Stage 1, ingestion: one capture reader (scapy; dumpcap for live) buckets IKE and ESP/AH packets into sessions keyed by IKE SPI or cookie pair, flags NAT traversal, incomplete (mid-session) captures and fragmented IKE.
Stage 2, IKE parser: a pure-struct decoder for IKEv2 (RFC 7296) and IKEv1 (RFC 2408/2409, Main, Aggressive and Quick Mode). Aggressive Mode is detected from the ID payload in message 1, not from message count, so retransmissions cannot flip it. PFS is inferred only from a second DH exchange, never guessed.
Stage 3, flow features: a 13-feature metadata vector per flow (packet-size mean/std/p10/p90, inter-arrival mean/std, direction ratio, burst count and gap ratio, payload-size variance in bursts, duration, packet count, rate).
Stage 4a, protocol classification: deterministic first, with a light ML fallback for malformed or truncated handshakes.
Stage 4b, traffic-type classification: RandomForest and XGBoost auto-selected by macro-F1, with confusion matrix, per-class precision/recall/F1, feature importance, per-prediction explanations and an abstain threshold.
Stage 4c, security assessment: 21 YAML rules, scored per session and mapped to five compliance baselines. Hidden fields show "not assessed" instead of a false pass.
Stage 5, reports: risk score, threat matrix, AI confidence score, executive PDF (one page, plain English) and technical report (full session table, CVE/RFC links, vendor configuration fixes, confusion matrix), plus JSON and CEF export.
Stage 6, dashboard: Next.js console with capture upload, session table, drilldown, peer graph, aggregate charts, live stream, export and capture comparison.

3. COVERAGE OF EVERY REQUIREMENT IN THE BRIEF

(a) VPN testbed generation: done. Real strongSwan tunnels across 136 distinct configurations: tunnel 163 / transport 137, IPv4 152 / IPv6 148, PFS enabled 147 / disabled 153, six ciphers, three DH groups, six traffic classes.
(b) Traffic capture: IKE negotiation and ESP are captured with tcpdump/dumpcap and read by scapy. AH packets are parsed by the capture reader; the dataset itself contains ESP only (AH is optional in the brief).
(c) AI-based protocol identification: IPsec protocol (ESP/AH), IKE version, encryption algorithm, integrity algorithm, PRF, key-exchange group, SA lifetime and PFS are read from the negotiation (IKE version, cipher, integrity and DH group were recovered on 300 of 300 captures). Tunnel vs transport mode and authentication method are inside the encrypted IKE_AUTH exchange, so they are reported as "unknown" unless they can be inferred (mode is inferred from ESP packet sizes and marked "inferred" with a confidence) or supplied by imported gateway state (swanctl, ip xfrm). Traffic type inside ESP is predicted by the ML classifier.
(d) Security assessment: cryptographic strength, cipher-suite strength, DH group (MODP768/1024 broken or LOGJAM-class), integrity (MD5/SHA-1), SA parameters, key lifetime (over 8h / over 24h), replay protection (RFC 4303), Perfect Forward Secrecy, IKEv1 and Aggressive Mode exposure, certificate expiry, DPD, vendor CVEs, and metadata exposure. Configuration compliance is scored against NIST SP 800-77r1/800-131A, BSI TR-02102-3, CNSA 2.0, CERT-In and TEC ITSAR (the last two are indicative mappings). Post-quantum readiness (RFC 9370 hybrid IKEv2 / ML-KEM) is reported as an advisory.
(e) Output: comprehensive risk score (0-100), threat matrix, AI confidence score, traffic analysis and metadata inference, executive report and technical report, JSON/CEF export.
Deliverables: working prototype, AI classification engine, interactive dashboard, security assessment report, demonstration video, technical documentation (README, design document, dataset datasheet) and the dataset used for training and testing.

4. INNOVATION AND DIFFERENTIATION

- It is not Wireshark plus a classifier. The decoder is hand-written from the RFCs, with no Wireshark dependency in the parsing logic, and the correctness details are real (for example the IKEv2 transform "last substructure" byte, and mode detection that survives retransmission).
- Two honest AI problems instead of one marketing claim: deterministic identification where the protocol declares the answer, ML only where the data is encrypted.
- Behavioural attack detection across sessions, with the exact pcap frame numbers as evidence, rather than static configuration review only.
- A first-party labeled dataset. We found no public IPsec/ESP dataset that carries both per-tunnel crypto labels and traffic-class labels, so we generated one from real tunnels.
- Metadata exposure treated as a first-class assessment dimension: what an observer can learn about the tunnel without keys.
- A tamper-evident, hash-chained audit log of every analysis (a hash chain, not a blockchain), which fits the Cybersecurity theme.

5. TECHNICAL APPROACH AND STACK

Python 3.11, scapy, scikit-learn, XGBoost, FastAPI, SQLite, Jinja2 + WeasyPrint, Next.js, Tailwind, Recharts, D3, Docker Compose. Analysis works on uploaded PCAP/PCAPNG or on a live interface (dumpcap), and a hosted instance replays a bundled capture through the same live pipeline. It never needs the tunnel keys. The rule table is data (YAML), not code, so new weaknesses are added without redeploying logic.

6. FEASIBILITY AND VIABILITY

The prototype is built and running, not proposed: 380 Python tests, 57 frontend unit tests and 23 end-to-end tests run in CI, and the whole stack starts with one docker compose command. A warm analysis of a 2,884-packet capture takes about one second; the first call after a cold start takes longer while models load.
Risks and mitigations:
- Encrypted payload: only observable metadata is used, and results carry confidence with an abstain threshold.
- Limited labeled data: a reproducible testbed generates the dataset, with a published datasheet and validator.
- Configuration diversity: a full configuration matrix and held-out evaluation by cipher, DH group and mode.
- Wrong classification: deterministic validation first, ML confidence second, "unknown" over a guess.

7. HONEST LIMITATIONS

- Macro-F1 0.98 (n_test = 45) is an upper bound, not a field number: each lab capture holds exactly one traffic class, with no competing flows. Real traffic will score lower.
- The "WhatsApp" class is a substitute bursty chat generator, labeled as such, because a real messaging client cannot run in an isolated lab.
- The captured dataset is IKEv2 with pre-shared keys. IKEv1 is supported by the parser and tested on constructed handshakes, but not on real captures.
- Mode, PFS and authentication are encrypted in IKE_AUTH; without keys or gateway state they are inferred or reported "unknown", which is a deliberate false negative.
- Analysis is offline or passive-live; it is not an inline enforcement device.

8. IMPACT AND BENEFITS

Analysts get a scored, referenced verdict on an IPsec deployment in seconds instead of reading packets. Auditors get a finding list mapped to national and international baselines with vendor-specific fixes. The dataset and testbed let others reproduce and extend the work. Current workflow: capture, inspect in Wireshark, work out the configuration, judge the cryptography, check compliance, write a report. VaultScope workflow: upload or capture, automated identification and assessment, risk score and threat matrix, generated reports.

9. REFERENCES AND STANDARDS

RFC 7296 (IKEv2), RFC 2408 and RFC 2409 (ISAKMP/IKEv1), RFC 4301 and RFC 4303 (IPsec architecture, ESP and replay protection), RFC 3947 (NAT-T), RFC 7427 (signature authentication), RFC 9370 (multiple key exchanges in IKEv2), NIST SP 800-77r1, NIST SP 800-131A, NIST IR 8547, BSI TR-02102-3, CNSA 2.0, CVE-2016-1287, LOGJAM, SWEET32; strongSwan documentation; research literature on encrypted traffic classification from packet-size and timing side channels.
```

## Before pasting

1. Convert the filled SIH2026 PPTX to PDF (the portal wants a PDF, up to 10 MB).
2. Add the demo-video URL wherever the template asks for it. The video link is not part of these three text fields.
3. Re-check the numbers in section 6 if anything changes before submission.
