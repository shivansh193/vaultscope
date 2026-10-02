# SIH26160 portal answers (draft, paste-ready)

Every number below was checked against the repo on 2026-09-30 (after commit 11ed3e6): 378 pytest tests, 57 vitest, 23 Cypress, 21 rules, 300 labeled captures, macro-F1 0.9801 on n_test=45 (`models/eval_metrics.json`).

## Proposed Solution

VaultScope answers two different questions about an IPsec tunnel, and treats them as two different problems.

**What crypto is this tunnel using?** This is not machine learning. IKE negotiates in cleartext, so a from-scratch RFC 7296 / RFC 2408 byte decoder reads version, mode, cipher, integrity, PRF, DH group, PFS, lifetime and vendor fingerprint directly. ML is used only as a fallback for truncated or malformed handshakes.

**What is inside the encrypted ESP tunnel?** This is the real ML problem. The payload is encrypted, so a RandomForest/XGBoost classifier predicts VoIP, Video, Web, Email, Chat or ICMP from metadata alone: packet-size distribution, inter-arrival timing, direction ratio and burstiness.

Around those two engines: a 21-rule data-driven security engine (each rule tied to a CVE, RFC or NIST reference) scored against five compliance baselines (NIST, BSI, CNSA 2.0, CERT-In, TEC ITSAR), a metadata-exposure score for what an observer learns without any keys, post-quantum readiness detection (RFC 9370 / ML-KEM), a runtime attack detector with exact pcap frame numbers as evidence, optional gateway-state import (swanctl, ip xfrm) that fills the fields the wire hides, a hash-chained tamper-evident audit log, executive and technical PDF reports, JSON/CEF export, and an interactive dashboard with live capture.

## Technical Approach

1. **Testbed.** Real strongSwan peers in Docker over the config matrix: tunnel/transport, AES-128/256/GCM/CBC+HMAC, MODP1024/2048/ECP256, PFS on/off, IPv4/IPv6. Six traffic generators ride each tunnel.
2. **Capture and ingestion.** One capture reader (scapy, dumpcap for live) buckets packets into sessions by IKE SPI/cookie pair and attaches the ESP stream.
3. **IKE parser.** Pure `struct` decoder for IKEv1 (Main, Aggressive, Quick Mode) and IKEv2. Aggressive Mode is detected from the ID payload in message 1, not from message count, so retransmissions cannot flip it.
4. **Flow features.** 13 metadata-only features per flow.
5. **Classifiers.** Stage 4a protocol identification (deterministic first), Stage 4b traffic-type model trained on the captured dataset, with confusion matrix and feature importance.
6. **Rules + anomalies.** Rules are YAML, not hardcoded. Six behavioural detectors (aggressive-mode probing, transform brute force, downgrade, NAT-T misuse, rekey storm, SPI collision).
7. **Reports and dashboard.** Risk score, threat matrix, AI confidence score, executive and technical reports; Next.js console.

## Feasibility and Viability

Already built and running, not proposed: 347 Python tests, 57 unit tests and 23 end-to-end tests run against the real stack in CI. Ships as a Docker Compose stack. Analysis is offline pcap or passive live capture, and it never needs the tunnel keys.

## Impact and Benefits

Analysts get a security verdict on an IPsec deployment without reading packets. Auditors get a scored, referenced finding list with vendor-specific fixes. **The 300-capture labeled dataset is itself a deliverable**: we found no public IPsec/ESP dataset with per-tunnel crypto labels and traffic-class labels, so we built one from real strongSwan tunnels.

## Research and References

RFC 7296 (IKEv2), RFC 2408/2409 (IKEv1), RFC 4303 (ESP, replay protection), RFC 3947 (NAT-T), RFC 7427, NIST SP 800-77r1, NIST SP 800-131A, CVE-2016-1287, LOGJAM, SWEET32.

## Honesty statement (keep next to any accuracy number)

Macro-F1 0.98 is an upper bound, not a field number: each lab capture holds one traffic class and the lab has no cross-traffic. On the IKEv2 captures, cipher, integrity, DH group and version are recovered 300/300. Mode, PFS and peer auth sit inside the encrypted IKE_AUTH exchange and are reported `unknown` rather than guessed, which is a deliberate false negative. The "WhatsApp" class is a bursty chat-sized generator, labeled as a substitute.
