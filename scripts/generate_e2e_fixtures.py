"""Build the pcaps the Cypress specs upload (spec Section 9, P4).

Reuses Block A's wire builders so the e2e fixtures are the same synthetic
handshakes the Stage 2 parser is tested against -- there is no second
definition of "a weak capture" anywhere.

    python scripts/generate_e2e_fixtures.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "e2e" / "fixtures"
sys.path[:0] = [str(ROOT), str(ROOT / "tests" / "ike_parser")]

import _build as B  # noqa: E402  (needs the path insert above)

# Distinct initiator SPIs so the parser buckets these as separate sessions.
PRESETS = ("aes256gcm_ecp521_pfs", "aes128cbc_sha256_modp2048", "3des_sha1_modp1024")


def retag(messages: list[bytes], tag: int) -> list[bytes]:
    return [bytes([tag]) + m[1:] for m in messages]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # One CRITICAL session: IKEv1 Aggressive Mode, DES/MD5/PSK/MODP1024.
    B.write_pcap(OUT / "test_weak.pcap", B.v1_aggressive_mode())

    # A mixed capture: four IKEv2 SAs across the cipher presets plus the weak
    # IKEv1 one, so the table has something to sort and filter.
    mixed: list[bytes] = []
    for tag, preset in enumerate(PRESETS + (PRESETS[0],), start=1):
        mixed += retag(B.sa_init_for_preset(preset), tag)
    mixed += B.v1_aggressive_mode()
    B.write_pcap(OUT / "test_mixed.pcap", mixed)

    for pcap in sorted(OUT.glob("*.pcap")):
        print(f"{pcap.relative_to(ROOT)}  {pcap.stat().st_size} bytes")


if __name__ == "__main__":
    main()
