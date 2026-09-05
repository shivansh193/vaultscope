"""The Stage 0 configuration matrix (spec Section 3).

One place that knows both strongSwan's proposal keywords and the canonical
``core.models.IkeParams`` vocabulary, so a generated tunnel and its
ground-truth label cannot drift apart.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CipherSuite:
    slug: str
    encryption: str  # core.models vocabulary
    integrity: str  # "implicit" for AEAD, matching IkeParams' own default
    ike_proposal: str  # strongSwan keyword, minus the DH group
    esp_proposal: str


# AEAD suites carry no separate integrity transform; "implicit" is the value
# core.models.IkeParams already uses for exactly that.
CIPHER_SUITES: list[CipherSuite] = [
    CipherSuite("aes128cbc_sha256", "AES-128-CBC", "HMAC-SHA256", "aes128-sha256", "aes128-sha256"),
    CipherSuite("aes256cbc_sha256", "AES-256-CBC", "HMAC-SHA256", "aes256-sha256", "aes256-sha256"),
    CipherSuite("aes128gcm", "AES-128-GCM", "implicit", "aes128gcm16-prfsha256", "aes128gcm16"),
    CipherSuite("aes256gcm", "AES-256-GCM", "implicit", "aes256gcm16-prfsha384", "aes256gcm16"),
    CipherSuite("3descbc_sha1", "3DES-CBC", "HMAC-SHA1", "3des-sha1", "3des-sha1"),
    CipherSuite("descbc_md5", "DES-CBC", "HMAC-MD5", "des-md5", "des-md5"),
]

# (label slug, strongSwan keyword). MODP1024 is here on purpose: rule R03 fires
# on it, and a dataset of only healthy tunnels would prove nothing about
# Stage 4c.
DH_GROUPS: list[tuple[str, str]] = [
    ("modp1024", "modp1024"),
    ("modp2048", "modp2048"),
    ("ecp256", "ecp256"),
]

MODES: list[str] = ["tunnel", "transport"]
IP_VERSIONS: list[str] = ["IPv4", "IPv6"]
