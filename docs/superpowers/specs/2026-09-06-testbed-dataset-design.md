# Stage 0 testbed and the labeled dataset (P1-T1..T4)

Design for sub-project A of the remaining Block A work. Sub-projects B
(ingestion + parser edge cases) and C (flow features + classifiers) get their
own specs; C is blocked on this one because it needs the dataset.

## Why this exists

The labeled dataset is an explicit deliverable of the problem statement, not a
means to an end: deliverable 1 in spec Section 13, `data/` zippable, class
balance tested. It is also the only possible input to Stage 4b, which is the
project's one genuine ML component.

Today `data/pcaps/` and `data/labels/` hold nothing but `.gitkeep`.

## Feasibility, already established

A throwaway probe on 2026-09-06 confirmed the whole chain works on this
machine:

- Docker Desktop's linuxkit kernel (6.12.5) has xfrm and pfkey.
- Two `debian:bookworm-slim` containers running strongSwan established a real
  IKEv2 SA (AES-256-CBC / HMAC-SHA256 / MODP2048, ESP AES-GCM-256), passed
  ping traffic, and tcpdump captured IKE + ESP.
- `core.ike_parser.parse_ikev2_sessions()` read that capture back and
  recovered the crypto parameters correctly, with a session id matching the
  SPIs strongSwan itself reported.

Two things the probe found that this design has to account for:

1. **The slim strongSwan install has no crypto backend.** `strongswan` alone
   omits the openssl and gcrypt plugins, and every connection fails to load.
   The image must also install `libstrongswan-standard-plugins`,
   `libstrongswan-extra-plugins` and `libcharon-extra-plugins`.
2. **Docker's NAT puts IKE on UDP 4500**, so every captured session reads
   `nat_traversal = true`. That is a property of the harness, not of the
   configuration under test, and the label JSON must say so rather than let a
   consumer read it as a finding.

(A third finding, that the parser reports `auth_method = "RSA"` for a PSK
tunnel because IKE_AUTH is encrypted and the model default fills the gap,
belongs to sub-project B. It is recorded here only so it is not lost.)

## Components

Four units, each independently testable.

### 1. Config generator — `testbed/config_generator.py`

Pure function of the matrix; no Docker, no I/O beyond writing files.

`generate_configs()` returns a list of `TunnelConfig` records over the
cartesian product from spec Section 3:

| Dimension | Values |
|---|---|
| mode | tunnel, transport |
| cipher suite | AES-128-CBC+SHA256, AES-256-CBC+SHA256, AES-128-GCM, AES-256-GCM, 3DES-CBC+SHA1, DES-CBC+MD5 |
| DH group | MODP1024, MODP2048, ECP256 |
| PFS | on, off |
| IP version | IPv4, IPv6 |

144 cells (2 x 6 x 3 x 2 x 2). Each record renders to a pair of `swanctl.conf` files (initiator and
responder) through one template.

Naming follows the spec's regex, with the traffic class appended after a double
underscore so the config name stays matchable on its own:

```
<mode>_<cipher>_<group>_(pfs|nopfs)_(ipv4|ipv6)__<class>
tunnel_aes256gcm_modp2048_pfs_ipv4__voip
```

The weak suites (DES+MD5, 3DES+SHA1, MODP1024) are deliberately in the matrix.
They are what make the rule engine's output non-trivial, and a dataset of
uniformly healthy tunnels would prove nothing about Stage 4c.

### 2. Peer harness — `testbed/harness.py`

Brings up one peer pair for one config and tears it down again.

- Creates a dedicated Docker network per pair (`10.90.<n>.0/24`, or
  `fd00:90:<n>::/64` for the IPv6 cells) so pairs can run concurrently without
  colliding.
- Starts two containers from the testbed image, mounting the generated
  `swanctl.conf`.
- Starts charon, loads the config, initiates the child SA, and waits for
  `swanctl --list-sas` to report ESTABLISHED, with a timeout.
- On any failure: capture charon's log into the run report and move on. One
  cell that will not establish must not sink a 300-cell run.

A context manager, so teardown happens on exception.

### 3. Traffic generators — `testbed/generators/`

One container image per class, all traffic addressed to the responder's tunnel
address so it rides the SA.

| Class | Generator | Real protocol? |
|---|---|---|
| Web | nginx on the responder, curl looping fetches of mixed-size objects | yes |
| Video | ffmpeg streaming a generated test pattern over RTP | yes |
| VoIP | sipp UAC/UAS pair with a G.711 RTP media stream | yes |
| Email | Postfix on the responder, swaks sending messages with attachments | yes |
| ICMP | ping at a fixed interval | yes |
| Chat | scripted bursty sender: short messages, human-like idle gaps | **no — substitution** |

Chat is the spec's own acknowledged WhatsApp substitution. It is marked
`"substitution": true` in every label JSON it produces, and any reporting of
per-class accuracy has to carry that through.

### 4. Dataset runner — `scripts/generate_dataset.py`

The only entry point a person runs.

```
python scripts/generate_dataset.py --target 300 --duration 30 --parallel 4
```

For each sampled cell: bring up the pair, start `tcpdump -w` on the initiator
filtered to `udp port 500 or udp port 4500 or esp`, run the generator for
`--duration`, stop capture, copy the pcap out, write the label JSON, tear down.

**Sampling.** 144 cells x 6 classes is 864 combinations; the deliverable asks
for >=300 files. The runner takes a stratified sample rather than the head of
the list: every cipher suite, every DH group and both PFS states must appear in
every traffic class, and the remainder is filled at random under a fixed seed
so a run is reproducible. Roughly 50 pcaps per class.

**Duration.** 30 seconds per capture, not the spec's 120. The flow statistics
Stage 3 extracts (packet size distribution, inter-arrival timing, burstiness,
direction ratio) are stable well inside 30s, and 120s x 300 is ten hours of
wall clock for no additional signal. This is a deliberate deviation from spec
Section 8 and is recorded in the dataset README.

**Parallelism.** Four pairs at a time on separate subnets. ~300 captures at 30s
over 4 workers is roughly 40 minutes.

**Resumability.** A cell whose pcap and label already exist is skipped, so an
interrupted run continues rather than restarting.

## Data flow

```
config_generator.generate_configs()
        |
        v  TunnelConfig
   harness.peer_pair(config)  --> two containers, SA established
        |
        v
   generator.run(class, duration)  --> traffic across the SA
        |
        v  tcpdump on initiator
   data/pcaps/<name>.pcap  +  data/labels/<name>.json
```

## Label schema

One JSON per pcap, same basename. This is ground truth, so it records what was
*configured*, never what a parser recovered.

```json
{
  "pcap": "tunnel_aes256gcm_modp2048_pfs_ipv4__voip.pcap",
  "traffic_class": "VoIP",
  "substitution": false,
  "generator": "sipp 3.6.0, G.711 RTP",
  "duration_sec": 30,
  "config": {
    "mode": "tunnel",
    "encryption": "AES-256-GCM",
    "integrity": "implicit",
    "dh_group": "MODP2048",
    "pfs": true,
    "ip_version": "IPv4",
    "auth_method": "PSK",
    "ike_version": "IKEv2"
  },
  "harness_notes": [
    "IKE observed on UDP 4500: Docker's NAT triggers NAT-T. An artifact of the harness, not of the configuration."
  ],
  "captured_at": "2026-09-06T12:00:00Z",
  "testbed_commit": "<git sha>"
}
```

`integrity: "implicit"` for the GCM suites, matching `core.models.IkeParams`'s
own default and vocabulary. Field names and values reuse the canonical model's
vocabulary throughout so a label can be compared to a parsed session without a
translation layer.

## Error handling

- **A cell will not establish.** Log charon's output, record the cell as failed
  in the run report, continue. The run report is written at the end and lists
  every failure with its reason.
- **A generator produces no traffic.** The capture is checked for a minimum
  packet count before its label is written; below it, the cell is failed rather
  than silently yielding an empty pcap.
- **Docker is not running.** Fail immediately with a clear message, before
  generating anything.
- **Interrupted run.** Already-complete cells are skipped on the next
  invocation.

## Testing

| Test | What it pins | Marker |
|---|---|---|
| `tests/testbed/test_config_generator.py::test_all_cipher_configs_generated` | >= 96 configs from the matrix | — |
| `...::test_config_naming_convention` | the spec's naming regex | — |
| `...::test_strongswan_config_syntax_valid` | `swanctl --load-conns` returns 0 on generated configs | `slow` |
| `tests/testbed/test_harness.py` | a pair establishes and tears down | `slow` |
| `tests/dataset/test_dataset_class_balance.py::test_dataset_class_balance` | deliverable 1: >= 300 files, all six classes present, no class below a floor | `slow` |
| `...::test_label_schema_valid` | every label JSON parses and carries the required keys | `slow` |

The first two run in the normal suite; everything needing Docker or a generated
dataset is marked `slow`, consistent with the existing `pytest -m "not slow"`
convention.

## What this deliberately does not do

- **No live-NIC capture.** Stage 1's live path is sub-project B's concern.
- **No IKEv1 cells in the first pass.** strongSwan's IKEv1 support is legacy
  and configuring it doubles the matrix. The parser's IKEv1 path is already
  covered by synthetic fixtures in `tests/ike_parser/`. If the dataset needs
  real IKEv1 captures later, it is a new cell dimension, not a redesign.
- **No cross-traffic noise.** The dataset is lab-clean by construction, which
  the LLD already names as a disclosed limitation. Real-world accuracy will be
  lower and the model card has to say so.
