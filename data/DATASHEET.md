# Datasheet: VaultScope IPsec capture corpus

Deliverable 1 of SIH26160. Format loosely follows *Datasheets for Datasets*
(Gebru et al.). Schema, naming and regeneration steps are in
[`README.md`](README.md); this page records what the corpus contains and
what it should not be used for.

## At a glance

| | |
|---|---|
| Captures | 300 pcaps, one IKEv2 tunnel each, 30 s of one traffic class |
| Labels | 300 JSONs in `labels/`, the **configured** ground truth |
| Size | ~129 MB of pcaps |
| Integrity | SHA-256 of every pcap in [`MANIFEST.sha256`](MANIFEST.sha256) (`sha256sum -c` format) |
| Download | see *Distribution* below |
| Check | `python scripts/validate_dataset.py --require-pcaps` |

## Composition

| Class | Captures | Generator | Real protocol? |
|---|---:|---|---|
| ICMP | 57 | ping | yes |
| VoIP | 57 | sipp, G.711-rate RTP | yes |
| Web | 51 | curl against nginx | yes |
| Video | 49 | ffmpeg, H.264 over RTP | yes |
| Email | 48 | swaks, base64 attachments over SMTP | yes |
| Chat | 38 | scripted bursty sender | **no, it's a substitute** (`"substitution": true`) |

### Matrix coverage per class

Every value of every matrix dimension appears in every traffic class (the
smallest cell is AES-256-GCM × Chat, 3 captures).

| Dimension | Value | VoIP | Video | Web | Email | ICMP | Chat | Total |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Mode | transport | 29 | 20 | 21 | 23 | 24 | 20 | 137 |
| Mode | tunnel | 28 | 29 | 30 | 25 | 33 | 18 | 163 |
| Cipher | 3DES-CBC | 9 | 8 | 7 | 7 | 13 | 7 | 51 |
| Cipher | AES-128-CBC | 11 | 9 | 12 | 10 | 6 | 9 | 57 |
| Cipher | AES-128-GCM | 9 | 10 | 7 | 9 | 8 | 7 | 50 |
| Cipher | AES-256-CBC | 7 | 9 | 10 | 8 | 11 | 7 | 52 |
| Cipher | AES-256-GCM | 10 | 7 | 6 | 6 | 9 | 3 | 41 |
| Cipher | DES-CBC | 11 | 6 | 9 | 8 | 10 | 5 | 49 |
| DH group | ECP256 | 18 | 15 | 19 | 14 | 24 | 12 | 102 |
| DH group | MODP1024 | 16 | 17 | 20 | 16 | 18 | 13 | 100 |
| DH group | MODP2048 | 23 | 17 | 12 | 18 | 15 | 13 | 98 |
| PFS | disabled | 33 | 28 | 29 | 22 | 24 | 17 | 153 |
| PFS | enabled | 24 | 21 | 22 | 26 | 33 | 21 | 147 |
| IP version | IPv4 | 29 | 22 | 29 | 23 | 30 | 19 | 152 |
| IP version | IPv6 | 28 | 27 | 22 | 25 | 27 | 19 | 148 |

Authentication is PSK on all 300. The full matrix (2 modes × 6 ciphers × 3 DH
groups × 2 PFS × 2 IP versions) has 144 configurations; the stratified sample
covers **136** of them. The eight configurations with no capture are:

`tunnel_aes256cbc_sha256_modp1024_nopfs_ipv6`,
`tunnel_aes128gcm_modp2048_nopfs_ipv4`,
`tunnel_aes256gcm_modp1024_nopfs_ipv4`,
`tunnel_3descbc_sha1_modp1024_nopfs_ipv4`,
`tunnel_3descbc_sha1_modp1024_nopfs_ipv6`,
`transport_aes256gcm_modp1024_pfs_ipv6`,
`transport_3descbc_sha1_modp2048_nopfs_ipv6`,
`transport_descbc_md5_ecp256_nopfs_ipv6`.

IPv6 and transport mode are populated in the captures themselves, not just
defined in `testbed/matrix.py`: 148 IPv6 captures, 137 transport captures.

## Collection

Two strongSwan peers in Docker on a private bridge network. The initiator runs
tcpdump from before `swanctl --initiate`, so each capture holds the full
IKE_SA_INIT exchange plus the ESP data plane. One generator runs for 30 s, and
the capture is kept only if it holds at least 20 packets.
`scripts/generate_dataset.py --from-labels` rebuilds exactly the 300 cells the
labels name. It takes about 3 hours at `--parallel 4` on a laptop.

The labels record `captured_at` and `testbed_commit` for the capture they sit
beside, so the corpus in the release and the labels in git always describe the
same files. The manifest ties them together.

## Uses

- Training and evaluating the Stage 4b traffic-type classifier, and the mode
  model. `python -m core.classifiers.heldout` reproduces every held-out
  number in the README.
- Regression tests for the parser, since the parsed crypto must match the label
  (`tests/dataset/`).

**Do not** use it as evidence of field accuracy. See the limits below.

## Known limits

1. **Lab-clean.** Each capture has one tunnel and one class, with no competing
   flows, loss or background noise. Accuracy measured here is an upper bound.
2. **Volume identifies the class.** Each generator runs at a fixed rate for a
   fixed 30 s, so packet count and rate alone separate most classes. The
   held-out report includes an ablation without those features.
3. **Chat is a substitute** for real messaging traffic.
4. **Every capture shows NAT-T**, because Docker's bridge NATs. This is a
   harness property, not a configuration property.
5. **IKEv2 only, PSK only, strongSwan only.** Other implementations
   (Libreswan, OpenBSD iked, vendor gateways) are untested.
6. **Captures are 30 s**, not the spec's 120 s (see `README.md`).

## Distribution

The pcaps are not in git. They are published as a release asset with the
manifest:

- **Corpus:** `<RELEASE-URL-PLACEHOLDER>` (`vaultscope-corpus.tar.gz`)

```bash
tar -xzf vaultscope-corpus.tar.gz -C data/pcaps
python scripts/validate_dataset.py --require-pcaps   # every hash must match
```
