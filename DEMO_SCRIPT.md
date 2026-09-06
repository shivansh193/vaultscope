# VaultScope — recorded demo script

**Total ≈ 3:20.** About 1:15 on the diagrams, 2:05 in the product.

**Before recording:** `docker compose up -d`, browser at <http://localhost:3000>,
`data/demo/demo_capture.pcap` ready to drag. Have the four diagrams open in
Preview so you can arrow between them.

Spoken lines are quoted. Actions in brackets. Timings are cumulative.

---

# Part 1 — The diagrams (0:00 – 1:20)

## 0:00 — 0:15 · Open cold

> "Every organisation runs IPsec VPNs. Almost nobody knows what cipher they
> actually negotiated.
>
> VaultScope takes a packet capture and tells you exactly what your VPNs are
> doing — passive, no agents, no keys, nothing on the gateways."

---

## 0:15 — 0:40 · Diagram 1 — the pipeline

[Show `01-pipeline`.]

> "Seven stages, all ours. Our own testbed generates the training data. A
> hand-written RFC 7296 decoder reads the handshake. Then three analyses run in
> parallel — a protocol classifier, the traffic classifier, and an
> eighteen-rule engine — converging into one scored record."

---

## 0:40 — 1:00 · Diagram 2 — the design decision

[Show `02-two-ai-problems`.]

> "This is the idea the product turns on.
>
> Identifying the crypto is **not** machine learning. IKE negotiates in
> cleartext before the tunnel exists, so the cipher, the DH group and the vendor
> are right there on the wire — we wrote a byte-level decoder and read them
> exactly. Wireshark isn't in our path.
>
> The real ML problem is what rode *inside* the tunnel. That payload stays
> encrypted — we hold no keys. What survives is metadata: packet sizes, timing,
> burstiness. Video and chat leave different shapes even when both are opaque."

---

## 1:00 — 1:20 · Diagrams 3 and 4 — the evidence

[Show `03-dataset-and-model`.]

> "No public dataset exists for IPsec ESP with per-tunnel crypto labels, so we
> built one: three hundred labeled captures from real tunnels across a 144-cell
> config matrix.
>
> The classifier scores **macro-F1 0.98 on held-out captures** — one Video flow
> called VoIP, everything else exact."

[Show `04-capture-journey`.]

> "And every stage reads and writes one canonical session record — parser,
> classifiers, rules, database, API, reports, dashboard. One shape throughout."

---

# Part 2 — The product (1:20 – 3:40)

## 1:20 — 1:35 · Upload

[Drag `demo_capture.pcap` onto the drop zone.]

> "One pcap. Six tunnels inside it."

[Redirects to the session table.]

---

## 1:35 — 2:00 · The session table

> "Every tunnel, decoded and scored. The strip along the top is the entire
> capture at a glance — three critical, one high, two clean.
>
> Encryption, Diffie-Hellman group, PFS status — all recovered from the
> handshake. And the Traffic column: VoIP, Video, Web, Chat, predicted from
> encrypted flows alone, with a confidence on each."

---

## 2:00 — 2:45 · The drilldown

[Click the top CRITICAL row — DES-CBC / MODP1024.]

> "Full decode. DES with MODP1024 — that's Logjam, CVE-2015-4000, and it's
> flagged with the reference.
>
> But here's what makes it useful: **the exact configuration change to fix it,
> for that vendor.** We fingerprint the implementation from the IKE Vendor ID
> payload — Cisco ASA, strongSwan, Juniper — so this isn't generic advice.
> These are the lines you paste into that box.
>
> Below it, the flow measurements the traffic prediction was made from. And
> every anomaly we raise carries the exact packet frame numbers, so anyone can
> open the pcap in Wireshark and verify us."

---

## 2:45 — 3:05 · Peer graph

[Click **Peers**. Drag a node.]

> "The same capture as a topology. Each node is a VPN peer, coloured by its
> **worst** session — so a single weak tunnel among twenty healthy ones still
> shows red, because that's the one someone has to go and fix. Click a peer and
> the table filters to it."

---

## 3:05 — 3:20 · Overview

[Click **Overview**.]

> "Risk distribution across the estate, the traffic mix inside the tunnels, and
> a threat matrix by likelihood and impact — every chart driven by the same
> session records."

---

## 3:20 — 3:40 · Export and close

[Click **Export**, trigger one download.]

> "Four artifacts, one click each: a one-page executive PDF for management, a
> full technical report with the confusion matrix embedded, JSON, and CEF that
> drops straight into a SIEM.
>
> Passive capture, to full IKE decode, to machine learning on encrypted traffic,
> to CVE-linked scoring, to a vendor-specific fix — and the labeled dataset
> underneath it is ours. That's VaultScope."

---

# Recording notes

- **Reset before you record:** `docker compose down && docker compose up -d`
  gives a clean console, so the upload is the first thing that populates it.
- **The drilldown is the money shot.** It's the longest beat on purpose — let
  the config diff sit on screen for a couple of seconds.
- **Drag a node** in the peer graph. Motion sells that it's a live force
  simulation, not a picture.
- Don't click **Live** — it streams on ingest and will look empty on its own.
- If you need to reach 3:00 flat, cut the Overview beat and shorten the
  pipeline walk to Stage 0, 2 and 4b.
