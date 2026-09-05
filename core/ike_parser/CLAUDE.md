# CLAUDE.md — `core/ike_parser/` (Stage 2, Block A / P2)

Reconstructs IKEv1 + IKEv2 handshakes from packets and fills the `ike` block of
the canonical `core.models.VPNSession`. Spec: §4 "Stage 2 - IKE Parser".

**Update this file when you change the module layout, the wire decoder, or the
mapping to `core.models.IkeParams`.**

## Module map

| File | Responsibility |
|---|---|
| `_transforms.py` | IANA/RFC constants + `canon_*` functions → the canonical strings downstream stages match on. IKEv2 constants unprefixed; IKEv1/ISAKMP constants `V1_*`. **These strings are a contract with Stage 4c's `rules.yaml` — don't rename casually** (e.g. AEAD integrity is `"implicit"`, DES is `"DES-CBC"`, group 2 is `"MODP1024"`). |
| `_wire.py` | Pure-`struct` RFC 7296 / RFC 2408 decoder. `decode_message(bytes) -> IkeMessage`. No scapy/pyshark. Frames generic payloads; `_decorate` fills per-type fields for known IKEv2 payloads. IKEv1 payloads are framed but left raw (v1 numbering ≠ v2) — `ikev1.py` interprets them. |
| `ikev2.py` | `parse_ikev2()` / `parse_ikev2_sessions()` → `core.models.VPNSession`. Also owns the shared source-ingestion helpers `_read_pcap` / `_normalise` / `_fill_ip_ctx` / `_PcapMessage` (version-agnostic; `ikev1.py` imports `_normalise`). |
| `ikev1.py` | `parse_ikev1()` / `parse_ikev1_sessions()` → `core.models.VPNSession`. Phase-1 (Main/Aggressive) only. |

There is **no `models.py` here** — one session shape lives in `core/models.py`.
`_analyse()` accumulates a plain `ike` dict of *observed* values and constructs
`IkeParams(**ike)` at the end.

## Mapping to `core.models.IkeParams`

- Only fields actually observed on the wire are set. Unset crypto fields fall
  to the `IkeParams` defaults — a **known gap** when `ike.capture_complete`
  is `False` (opaque/encrypted IKE_AUTH, mid-session capture). Consumers should
  gate on `capture_complete`.
- `auth_method`: this change **widened `core.models.IkeParams.auth_method`** to
  `Literal["PSK","RSA","DSS","ECDSA","EAP","XAUTH"] | None` (real IKE negotiates
  DSS/ECDSA; an opaque IKE_AUTH → `None`). Rules R06/R13 test `eq PSK`, so any
  other value is simply "not PSK".
- `integrity` for AEAD suites is `"implicit"` (matches the model default).
- ESP-only / no-handshake source → a `VPNSession(session_id="esp-only")` with
  `ike.capture_complete=False`, crypto fields `"unknown"`, `pfs_status="unknown"`.

## Wire-format gotchas (already handled — don't "fix" these)

- RFC 7296 §3.3.2 "Last Substruc" byte: **0 = last, 3 = more** (same for
  proposals: 0 = last, 2 = more). Easy to invert.
- **SK payload (IKEv2)** is ciphertext without keys. `_wire` best-effort parses
  the SK body as a payload chain: succeeds for key-logged / tshark-decrypted
  captures and synthetic fixtures, else `sk_opaque=True` and IKE_AUTH-derived
  fields are left unset.
- **Encrypted IKEv1 messages** (Main Mode 5-6): ENCRYPTION flag set →
  `decode_message` returns early with `encrypted=True`, `payloads=[]`.
- `_read_pcap` reads `udp.payload.original`, not `bytes(udp.payload)` — scapy
  binds UDP/500+4500 to its ISAKMP dissector and re-serialization can mangle an
  IKEv2 message.
- pcap reader handles: UDP 500, NAT-T UDP 4500 with the 4-byte non-ESP marker,
  skips ESP-in-UDP, notes bare ESP (proto 50) so a mid-session capture still
  yields a session id.

## Semantics worth knowing

- `ike.pfs_status` is `"unknown"` unless a CHILD_SA / Quick Mode negotiation was
  actually observed — never guessed. Spec §12 warns against a false
  `"disabled"` on incomplete captures (would misfire rule R10).
- `ike.mode` (`tunnel`/`transport`) is an IPsec/phase-2 property: IKEv2
  `USE_TRANSPORT_MODE` notify, or IKEv1 Quick Mode Encapsulation Mode attr.
  Left at `tunnel` when no phase-2 info is in the capture.
- **IKEv1: Quick Mode (phase 2) overrides phase 1** for `encryption`,
  `integrity`, `dh_group`, `mode`, `sa_lifetime_sec`. The IPsec SA is what
  protects data and is what Stage 4c should evaluate. `prf` / `aggressive_mode`
  stay phase-1 concepts. Quick Mode is encrypted → readable only for
  key-logged / decrypted captures + fixtures (`_wire` best-effort frames it).
- `aggressive_mode` (IKEv1): detected from an **ID payload in the SA-bearing
  message-id-0 message**, not message count (retransmissions change count).
  Exchange-type byte (2/4) is the fallback for mid-capture starts.

## Task status

| Task | State | Notes |
|---|---|---|
| P2-T1 IKEv2 parser | ✅ done | SA_INIT + IKE_AUTH → `core.models.VPNSession.ike` |
| P2-T2 IKEv1 Main/Aggressive | ✅ done | phase-1 params + mode detection |
| P2-T3 IKEv1 Quick Mode / PFS | ✅ done | KE/group → PFS, phase-2 cipher/integrity, encap → tunnel/transport (overrides phase 1) |
| P2-T4 edge cases / VID fingerprint | ⬜ next | fragmented IKE (`fragmented_ike`), vendor DB (`vendor`), anti-replay |

## Known gap found against real captures (P2-T4)

A real strongSwan tunnel authenticating with **PSK** parses as
`auth_method = "RSA"`. IKE_AUTH is encrypted in IKEv2 so the method genuinely
is not observable, but `IkeParams.auth_method` defaults to `"RSA"`, which
presents a guess as a fact. Rules **R06 and R13 test `eq PSK`**, so a PSK
tunnel never trips them. The honest value is `None` when IKE_AUTH could not be
read. Found against a testbed capture on 2026-09-06.

## Tests

`tests/ike_parser/` — `_build.py` synthesises RFC-accurate messages (no testbed
pcaps yet) and writes real pcaps via scapy; `conftest.py` exposes them as
fixtures. Run: `.venv/Scripts/python -m pytest tests/ike_parser -q`.
When P1's Stage 0 testbed lands, add real-capture regression tests alongside.
