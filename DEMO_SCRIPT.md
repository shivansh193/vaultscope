# VaultScope — 3-minute demo script

**Before you start:** `docker compose up -d`, open <http://localhost:3000>, and
have `data/demo/demo_capture.pcap` in a Finder window ready to drag.
Six tunnels, one file, deliberately spanning DES through AES-256-GCM.

Timings are cumulative. Spoken words are in quotes; actions are in brackets.

---

## 0:00 — 0:20 · The problem

> "Everyone runs IPsec VPNs. Almost nobody knows what cipher they actually
> negotiated — the config says one thing, what two peers agree on at 3am is
> another. `ike-scan` is active-only and unmaintained since 2012, Wireshark is
> manual, Tufin reads config files rather than the wire.
>
> VaultScope takes a capture and tells you what your VPNs are really doing."

---

## 0:20 — 0:40 · Upload

[Drag `demo_capture.pcap` onto the drop zone.]

> "One pcap, six tunnels inside it. No agents, no keys, nothing installed on the
> gateways — passive analysis of traffic you already have."

[It redirects to the session table.]

---

## 0:40 — 1:10 · The session table

> "Every tunnel, scored. The strip on top is the whole capture at a glance —
> three red, one amber, two clean.
>
> We recovered the encryption, the DH group and the PFS status for each.
> **That's not machine learning — IKE negotiates in cleartext before the tunnel
> exists, so we wrote a byte-level RFC 7296 decoder and read it.** The parser is
> ours; Wireshark isn't in the path.
>
> The Traffic column — VoIP, Video, Web, Chat — *that* is the ML. Two completely
> different problems, and we keep them apart."

---

## 1:10 — 1:50 · The drilldown — the money shot

[Click the top CRITICAL row, DES-CBC / MODP1024.]

> "Full decode on the left: DES, MODP1024, PFS we couldn't observe — and note it
> says *unknown*, not *disabled*. If the capture starts mid-session there's no
> second DH exchange to see, and guessing 'disabled' would invent a finding that
> isn't there.
>
> Then the violations, each tied to a real reference — MODP1024 is Logjam,
> CVE-2015-4000.
>
> And this is the part that matters operationally: **the exact config change to
> fix it, for that vendor.** We fingerprint the implementation from the IKE
> Vendor ID payload — Cisco ASA, strongSwan, Juniper — so this isn't generic
> advice, it's the lines you paste into that box.
>
> Down here are the flow measurements the traffic prediction came from. We never
> decrypt anything."

---

## 1:50 — 2:10 · Peer graph

[Click **Peers**.]

> "Same data as a topology. A node is a VPN peer, coloured by its *worst*
> session — so one weak tunnel among twenty good ones still shows red, because
> that's the one someone has to go fix. Drag them; click a peer to filter the
> table to it."

---

## 2:10 — 2:35 · Overview and the honest number

[Click **Overview**.]

> "Risk distribution, traffic mix, threat matrix.
>
> The classifier scores macro-F1 0.98 on held-out real captures — and I'll be
> straight about it. Our dataset is lab-clean: one class per capture, so they
> separate on coarse statistics. Real traffic interleaves and drops packets.
> **That's an upper bound, not a deployment claim** — which is why we ship the
> confusion matrix, not a headline figure."

---

## 2:35 — 2:50 · Export

[Click **Export**, hit one button.]

> "Four artifacts: a one-page executive PDF, a technical HTML report with the
> full inventory and the confusion matrix embedded, JSON, and CEF that drops
> straight into a SIEM."

---

## 2:50 — 3:00 · Close

> "And the dataset underneath all of this is ours: 300 labeled captures from
> real strongSwan tunnels we spin up in Docker across a 144-cell config matrix.
> That's a deliverable in its own right, and it's one command to regenerate."

---

# If they ask — the deeper cuts

**"Is this just Wireshark with a UI?"**
No. We wrote the IKE decoder from the RFC in pure `struct` — about 350 lines.
Wireshark isn't in the analysis path at all.

**"How do you detect Aggressive Mode?"**
By the ID payload appearing in the first message, not by counting messages.
Retransmissions change the count and break every count-based detector.

**"What attacks do you detect?"**
Six protocol-level detectors beyond the config rules: downgrade attempts,
transform brute-force, Aggressive Mode probing, SPI collision, rekey storms and
unexpected NAT-T. **Every anomaly carries the exact pcap frame numbers** — open
Wireshark and verify us.

**"What if the capture is incomplete?"**
Every session carries `capture_complete`, and any field we couldn't observe is
reported as unknown rather than defaulted. A partial decode never gets passed
off as an observation.

**"Can it run live?"**
Yes — the console holds a WebSocket to the backend and new sessions appear
within two seconds of detection. There's also a historical diff: load two
captures and see which peers appeared, which vanished, and which sessions got
*worse*. No other tool in this space does that diff.

**"How big is it?"**
~6,400 lines of Python, 22 React components, 278 tests passing, 18 security
rules each tied to a CVE, RFC or NIST reference. One `docker compose up`.

**Weakest point, if pressed:** the dataset is IKEv2-only and lab-clean, and the
Chat class is an acknowledged substitution — a real messaging client can't run
in an isolated lab. All three are written into the README, not buried.
