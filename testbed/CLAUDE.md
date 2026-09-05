# CLAUDE.md — Stage 0 testbed (P1)

Generates the labeled dataset by running real strongSwan tunnels in Docker.
Owned by Block B (@p4ralyn), covering Block A's P1 slice.

## Module map

| File | Responsibility |
|---|---|
| `matrix.py` | The config matrix. The one place that knows both strongSwan's proposal keywords and `core.models.IkeParams` vocabulary. |
| `config_generator.py` | Pure. `generate_configs()` enumerates 144 cells; `render_swanctl()` renders one peer's config. No Docker, no I/O. |
| `harness.py` | `peer_pair()` context manager: network, two containers, charon, teardown on exception. |
| `generators/run.py` | One generator per traffic class, plus `run_traffic()`. |
| `generators/chat.py` | The WhatsApp substitution. |
| `generators/smtp_sink.py` | Accepts swaks' mail so the Email class has a body. |
| `labels.py` | Ground-truth JSON per capture. |

`scripts/generate_dataset.py` is the entry point; `data/README.md` is the
dataset's own documentation.

## Gotchas that cost real time

These were all found by measuring rather than assuming. Each one produced a
result that *looked* fine.

- **Capture before establishing.** The IKE handshake happens inside
  `establish()`. Start tcpdump after it and the capture holds only the ESP data
  plane — which the Stage 2 parser reads as a crypto-less `esp-only` session,
  silently. No error, no warning, just no crypto. `capture_cell()` starts the
  capture first for exactly this reason.
- **Never `tcpdump -i any`.** It writes LINUX_SLL2, which scapy cannot decode;
  every packet reads as `Raw`. Bind to `eth0`.
- **Plain `strongswan` has no crypto backend.** Without
  `libstrongswan-standard-plugins`, `libstrongswan-extra-plugins` and
  `libcharon-extra-plugins`, every connection is discarded at load with
  `invalid value for: auth`.
- **`swanctl.conf` is newline-structured.** Semicolons do not parse.
- **Servers need `docker exec -d`.** `nohup a; b &` backgrounds only `b`, which
  silently left generator servers unstarted.
- **Debian Postfix rejects every recipient** here with `451 Temporary lookup
  failure`, and `postconf -e` does not persist in the slim image. Replaced with
  `smtp_sink.py`; swaks (the real client, and what shapes the traffic) is
  unchanged.

## Running one cell by hand

```python
from testbed import harness
from testbed.config_generator import generate_configs
from testbed.generators.run import run_traffic

harness.build_image()
config = next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))
with harness.peer_pair(config, index=90) as pair:
    pair.start_capture()
    pair.establish()
    run_traffic(pair, "Web", duration=10)
    pair.stop_capture()
    pair.copy_out(pair.initiator, "/tmp/capture.pcap", Path("/tmp/one.pcap"))
```

Check bytes actually crossed the SA with
`swanctl --list-sas --raw | grep bytes-out` — a generator that fails still
leaves a plausible-looking pcap full of handshake noise.

## Deviations from the spec

- **30s captures, not 120s.** Stage 3's statistics are stable well inside 30s;
  120s x 300 is ten hours for no extra signal.
- **IKEv2 only.** strongSwan's IKEv1 support is legacy and would double the
  matrix. The parser's IKEv1 path is covered by synthetic fixtures in
  `tests/ike_parser/`.
