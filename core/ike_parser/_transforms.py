"""IANA IKEv2 registry lookups and canonicalisation to VaultScope spec strings.

Sources:
  * RFC 7296 sections 3.1, 3.3.2
  * IANA "Internet Key Exchange Version 2 (IKEv2) Parameters"

Canonical output strings match the examples in the product spec Section 4
("Stage 2 - IKE Parser", "Output - VPNSession Object") and the config matrix
in Section 4 ("Stage 0"). The Stage 4c rule engine consumes these strings, so
keep them stable.
"""

from __future__ import annotations

# --- Exchange types (RFC 7296 section 3.1) --------------------------------------
EXCHANGE_IKE_SA_INIT = 34
EXCHANGE_IKE_AUTH = 35
EXCHANGE_CREATE_CHILD_SA = 36
EXCHANGE_INFORMATIONAL = 37

EXCHANGE_NAMES = {
    EXCHANGE_IKE_SA_INIT: "IKE_SA_INIT",
    EXCHANGE_IKE_AUTH: "IKE_AUTH",
    EXCHANGE_CREATE_CHILD_SA: "CREATE_CHILD_SA",
    EXCHANGE_INFORMATIONAL: "INFORMATIONAL",
}

# --- Payload types (RFC 7296 section 3.2) -------------------------------------
PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_IDI = 35
PAYLOAD_IDR = 36
PAYLOAD_CERT = 37
PAYLOAD_CERTREQ = 38
PAYLOAD_AUTH = 39
PAYLOAD_NONCE = 40
PAYLOAD_NOTIFY = 41
PAYLOAD_DELETE = 42
PAYLOAD_VENDOR_ID = 43
PAYLOAD_TSI = 44
PAYLOAD_TSR = 45
PAYLOAD_SK = 46
PAYLOAD_CP = 47
PAYLOAD_EAP = 48

# --- Transform types (RFC 7296 section 3.3.2) -------------------------------
TRANSFORM_TYPE_ENCR = 1
TRANSFORM_TYPE_PRF = 2
TRANSFORM_TYPE_INTEG = 3
TRANSFORM_TYPE_DH = 4
TRANSFORM_TYPE_ESN = 5

# Transform attribute type (RFC 7296 section 3.3.5): only Key Length matters here.
ATTR_KEY_LENGTH = 14

# --- Protocol IDs (RFC 7296 section 3.3.1) ----------------------------------
PROTOCOL_IKE = 1
PROTOCOL_AH = 2
PROTOCOL_ESP = 3

# --- Notify message types (RFC 7296 section 3.10.1 + IANA) ----------------
NOTIFY_NAT_DETECTION_SOURCE_IP = 16388
NOTIFY_NAT_DETECTION_DESTINATION_IP = 16389
NOTIFY_USE_TRANSPORT_MODE = 16391
NOTIFY_REKEY_SA = 16393
NOTIFY_IKEV2_FRAGMENTATION_SUPPORTED = 16430

# --- AUTH methods (RFC 7296 section 3.8 + RFC 7427) -----------------------
AUTH_METHOD_RSA_SIG = 1
AUTH_METHOD_SHARED_KEY_MIC = 2  # pre-shared key
AUTH_METHOD_DSS_SIG = 3
AUTH_METHOD_ECDSA_256 = 9
AUTH_METHOD_ECDSA_384 = 10
AUTH_METHOD_ECDSA_521 = 11
AUTH_METHOD_DIGITAL_SIGNATURE = 14  # RFC 7427, algorithm carried in the blob


# --- Encryption (Transform Type 1) ---------------------------------------------
_ENCR_AEAD = {14, 15, 16, 18, 19, 20, 28}  # AES-CCM-*, AES-GCM-*, ChaCha20-Poly1305


def is_aead_encr(transform_id: int) -> bool:
    return transform_id in _ENCR_AEAD


def canon_encryption(transform_id: int, key_length: int | None) -> str:
    """Return e.g. ``"AES-256-GCM"``, ``"3DES-CBC"``, ``"DES-CBC"``, ``"NULL"``.

    ``key_length`` is the negotiated Key Length attribute in *bits* (only present
    for variable-length ciphers such as AES); ``None`` when the peer omitted it.
    """
    kl = key_length
    if transform_id == 2:
        return "DES-CBC"
    if transform_id == 3:
        return "3DES-CBC"
    if transform_id == 11:
        return "NULL"
    if transform_id == 12:
        return f"AES-{kl or 128}-CBC"
    if transform_id == 13:
        return f"AES-{kl or 128}-CTR"
    if transform_id in (18, 19, 20):
        return f"AES-{kl or 128}-GCM"
    if transform_id in (14, 15, 16):
        return f"AES-{kl or 128}-CCM"
    if transform_id == 23:
        return f"CAMELLIA-{kl or 128}-CBC"
    if transform_id == 28:
        return "CHACHA20-POLY1305"
    return f"ENCR_{transform_id}"


# --- Integrity (Transform Type 3) --------------------------------------------
_INTEG_NAMES = {
    0: None,
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    5: "AES-XCBC",
    12: "HMAC-SHA256",
    13: "HMAC-SHA384",
    14: "HMAC-SHA512",
}


def canon_integrity(transform_id: int | None, *, aead: bool) -> str | None:
    if aead:
        return "implicit (AEAD)"
    if transform_id is None:
        return None
    return _INTEG_NAMES.get(transform_id, f"INTEG_{transform_id}")


# --- PRF (Transform Type 2) --------------------------------------------------
_PRF_NAMES = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
}


def canon_prf(transform_id: int | None) -> str | None:
    if transform_id is None:
        return None
    return _PRF_NAMES.get(transform_id, f"PRF_{transform_id}")


# --- Diffie-Hellman group (Transform Type 4) --------------------------------
_DH_NAMES = {
    0: None,
    1: "MODP768",
    2: "MODP1024",
    5: "MODP1536",
    14: "MODP2048",
    15: "MODP3072",
    16: "MODP4096",
    17: "MODP6144",
    18: "MODP8192",
    19: "ECP256",
    20: "ECP384",
    21: "ECP521",
    31: "Curve25519",
    32: "Curve448",
}


def canon_dh_group(group_num: int | None) -> str | None:
    if group_num is None:
        return None
    if group_num in _DH_NAMES:
        return _DH_NAMES[group_num]
    return f"DH_GROUP_{group_num}"


def canon_auth_method(method: int | None, *, eap: bool = False) -> str | None:
    """Collapse to the spec enum: ``PSK | RSA | EAP | XAUTH`` (+ ECDSA/DSS)."""
    if eap:
        return "EAP"
    if method is None:
        return None
    if method == AUTH_METHOD_SHARED_KEY_MIC:
        return "PSK"
    if method in (AUTH_METHOD_RSA_SIG, AUTH_METHOD_DIGITAL_SIGNATURE):
        return "RSA"
    if method == AUTH_METHOD_DSS_SIG:
        return "DSS"
    if method in (AUTH_METHOD_ECDSA_256, AUTH_METHOD_ECDSA_384, AUTH_METHOD_ECDSA_521):
        return "ECDSA"
    return f"AUTH_METHOD_{method}"
