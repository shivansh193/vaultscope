# CLAUDE.md — `core/ike_parser/` (Stage 2, Block A / P2)

Reconstructs IKEv1 + IKEv2 handshakes from packets into `VPNSession` records.
Spec: §4 "Stage 2 - IKE Parser", output schema §5.1 (`ike` sub-object).

**Update this file when you change the module layout, the wire decoder, or the
`VPNSession` schema.**

## Module map

| File | Responsibility |
|---|---|
| `_transforms.py` | IANA/RFC constants + `canon_*` functions → the canonical strings downstream stages match on. IKEv2 constants unprefixed; IKEv1/ISAKMP constants `V1_*`. **These strings are a contract with Stage 4c — don't rename casually.** |
| `_wire.py` | Pure-`struct` RFC 7296 / RFC 2408 decoder. `decode_message(bytes) -> IkeMessage`. No scapy/pyshark. Frames generic payloads; `_decorate` fills per-type fields for known IKEv2 payloads. IKEv1 payloads are framed but left raw (v1 numbering ≠ v2) — `ikev1.py` interprets them. |
| `models.py` | `VPNSession` dataclass. `to_ike_dict()` = spec §5.1 `ike` sub-object **verbatim** (key set is asserted in tests). |
| `ikev2.py` | `parse_ikev2()` / `parse_ikev2_sessions()`. Also owns the shared source-ingestion helpers `_read_pcap` / `_normalise` / `_fill_ip_ctx` / `_PcapMessage` (version-agnostic; `ikev1.py` imports `_normalise`). |
| `ikev1.py` | `parse_ikev1()` / `parse_ikev1_sessions()`. Phase-1 (Main/Aggressive) only. |

## Wire-format gotchas (already handled — don't "fix" these)

- RFC 7296 §3.3.2 "Last Substruc" byte: **0 = last, 3 = more** (same for
  proposals: 0 = last, 2 = more). Easy to invert.
- **SK payload (IKEv2)** is ciphertext without keys. `_wire` does a best-effort
  parse of the SK body as a payload chain: succeeds for key-logged /
  tshark-decrypted captures and synthetic fixtures, else `sk_opaque=True` and
  IKE_AUTH-derived fields stay `None`/`unknown`.
- **Encrypted IKEv1 messages** (Main Mode 5-6): ENCRYPTION flag set →
  `decode_message` returns early with `encrypted=True`, `payloads=[]`.
- `_read_pcap` reads `udp.payload.original`, not `bytes(udp.payload)` — scapy
  binds UDP/500+4500 to its ISAKMP dissector and re-serialization can mangle an
  IKEv2 message.
- pcap reader handles: UDP 500, NAT-T UDP 4500 with the 4-byte non-ESP marker,
  skips ESP-in-UDP, notes bare ESP (proto 50) so a mid-session capture still
  yields a session id.

## VPNSession semantics worth knowing

- `pfs_status` is `"unknown"` unless a CHILD_SA negotiation was actually
  observed — never guessed. Spec §12 explicitly warns against a false
  `"disabled"` on incomplete captures (would misfire rule R10).
- `mode` (`tunnel`/`transport`) is an IPsec/phase-2 property. IKEv1 phase-1
  leaves it at the `tunnel` default; Quick Mode sets it (P2-T3).
- `aggressive_mode` (IKEv1): detected from an **ID payload in the SA-bearing
  message-id-0 message**, not message count (retransmissions change count).
  Exchange-type byte (2/4) is the fallback for mid-capture starts.
- `confidence_source` = `"parser"` here; Stage 4a sets `"classifier"` for the
  RF fallback on ambiguous captures.

## Task status

| Task | State | Notes |
|---|---|---|
| P2-T1 IKEv2 parser | ✅ done (PR #2) | SA_INIT + IKE_AUTH → VPNSession |
| P2-T2 IKEv1 Main/Aggressive | ✅ done (stacked) | phase-1 params + mode detection |
| P2-T3 IKEv1 Quick Mode / PFS | ⬜ next | KE-in-QM → PFS, phase-2 cipher, tunnel/transport |
| P2-T4 edge cases / VID fingerprint | ⬜ | mid-session, fragmented IKE, vendor DB |

## Tests

`tests/ike_parser/` — `_build.py` synthesises RFC-accurate messages (no testbed
pcaps yet) and writes real pcaps via scapy; `conftest.py` exposes them as
fixtures. Run: `.venv/Scripts/python -m pytest tests/ike_parser -q`.
When P1's Stage 0 testbed lands, add real-capture regression tests alongside.
