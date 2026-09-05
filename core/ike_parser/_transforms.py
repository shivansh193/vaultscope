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
PAYLOAD_SKF = 53  # Encrypted and Authenticated Fragment (RFC 7383)

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
        return "implicit"  # matches core.models.IkeParams default for AEAD suites
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


# =========================================================================== #
# IKEv1 / ISAKMP  (RFC 2408 + RFC 2409)                                        #
# --------------------------------------------------------------------------- #
# IKEv1 payload numbering and phase-1 SA attributes differ from IKEv2, so they
# live in their own namespace (``V1_*``). D-H group numbers are shared with
# IKEv2, so ``canon_dh_group`` is reused.
# =========================================================================== #

IKE_VERSION_1 = 0x10

# ISAKMP header flags (RFC 2408 section 3.1)
V1_FLAG_ENCRYPTION = 0x01
V1_FLAG_COMMIT = 0x02
V1_FLAG_AUTH_ONLY = 0x04

# Exchange types (RFC 2408 section 3.1 + RFC 2409)
EXCHANGE_V1_BASE = 1
EXCHANGE_V1_IDENTITY_PROTECT = 2  # Main Mode
EXCHANGE_V1_AUTH_ONLY = 3
EXCHANGE_V1_AGGRESSIVE = 4  # Aggressive Mode
EXCHANGE_V1_INFORMATIONAL = 5
EXCHANGE_V1_QUICK = 32  # Quick Mode (phase 2)
EXCHANGE_V1_NEW_GROUP = 33

EXCHANGE_V1_NAMES = {
    EXCHANGE_V1_BASE: "Base",
    EXCHANGE_V1_IDENTITY_PROTECT: "Main Mode",
    EXCHANGE_V1_AUTH_ONLY: "Authentication Only",
    EXCHANGE_V1_AGGRESSIVE: "Aggressive Mode",
    EXCHANGE_V1_INFORMATIONAL: "Informational",
    EXCHANGE_V1_QUICK: "Quick Mode",
    EXCHANGE_V1_NEW_GROUP: "New Group Mode",
}

# Payload types (RFC 2408 section 3.1)
V1_PAYLOAD_NONE = 0
V1_PAYLOAD_SA = 1
V1_PAYLOAD_PROPOSAL = 2
V1_PAYLOAD_TRANSFORM = 3
V1_PAYLOAD_KE = 4
V1_PAYLOAD_ID = 5
V1_PAYLOAD_CERT = 6
V1_PAYLOAD_CERTREQ = 7
V1_PAYLOAD_HASH = 8
V1_PAYLOAD_SIG = 9
V1_PAYLOAD_NONCE = 10
V1_PAYLOAD_NOTIFICATION = 11
V1_PAYLOAD_DELETE = 12
V1_PAYLOAD_VENDOR_ID = 13
V1_PAYLOAD_NAT_D = 20  # RFC 3947
V1_PAYLOAD_NAT_OA = 21
V1_PAYLOAD_NAT_D_DRAFT = 130  # draft-ietf-ipsec-nat-t-ike-02/03
V1_PAYLOAD_NAT_OA_DRAFT = 131
V1_PAYLOAD_FRAGMENT = 132  # Cisco / draft-smyslov IKEv1 fragmentation

V1_DOI_IPSEC = 1

# Phase-1 SA attribute types (RFC 2409 Appendix A)
V1_ATTR_ENCRYPTION = 1
V1_ATTR_HASH = 2
V1_ATTR_AUTH_METHOD = 3
V1_ATTR_GROUP_DESC = 4
V1_ATTR_LIFE_TYPE = 11
V1_ATTR_LIFE_DURATION = 12
V1_ATTR_PRF = 13
V1_ATTR_KEY_LENGTH = 14

V1_LIFE_TYPE_SECONDS = 1
V1_LIFE_TYPE_KILOBYTES = 2

# RFC 2409 Appendix A "Encryption Algorithm". IDs 7 (AES-CBC) and 8
# (Camellia-CBC) are key-length dependent and handled in canon_v1_encryption.
_V1_ENCR_NAMES = {
    1: "DES-CBC",
    2: "IDEA-CBC",
    3: "BLOWFISH-CBC",
    4: "RC5-CBC",
    5: "3DES-CBC",
    6: "CAST-CBC",
}


def canon_v1_encryption(attr_id: int, key_length: int | None) -> str:
    if attr_id == 7:  # AES-CBC
        return f"AES-{key_length or 128}-CBC"
    if attr_id == 8:  # Camellia-CBC
        return f"CAMELLIA-{key_length or 128}-CBC"
    return _V1_ENCR_NAMES.get(attr_id, f"ENCR_{attr_id}")


_V1_HASH_INTEG = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    4: "HMAC-SHA256",
    5: "HMAC-SHA384",
    6: "HMAC-SHA512",
}
_V1_HASH_PRF = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    4: "PRF_HMAC_SHA2_256",
    5: "PRF_HMAC_SHA2_384",
    6: "PRF_HMAC_SHA2_512",
}


def canon_v1_integrity(hash_id: int | None) -> str | None:
    if hash_id is None:
        return None
    return _V1_HASH_INTEG.get(hash_id, f"HASH_{hash_id}")


def canon_v1_prf(hash_id: int | None) -> str | None:
    if hash_id is None:
        return None
    return _V1_HASH_PRF.get(hash_id, f"PRF_{hash_id}")


def canon_v1_auth_method(method: int | None) -> str | None:
    """RFC 2409 Appendix A + XAUTH (draft-beaulieu-ike-xauth, Cisco 65001-65004)."""
    if method is None:
        return None
    if method == 1:
        return "PSK"
    if method == 2:
        return "DSS"
    if method in (3, 4, 5):
        return "RSA"
    if 65001 <= method <= 65010 or method in (128, 129, 130, 131):
        return "XAUTH"
    return f"AUTH_METHOD_{method}"


# --- IKEv1 Phase 2 / Quick Mode  (RFC 2407 - the IPSEC DOI) ------------------
# Quick Mode SA attributes are numbered DIFFERENTLY from phase 1, and the
# transform *id* itself is the ESP/AH cipher (phase 1's transform id is always
# KEY_IKE=1 and the cipher rides in an attribute).

# IPSEC ESP transform identifiers (RFC 2407 section 4.4.4 + IANA additions)
_V1_ESP_NAMES = {
    2: "DES-CBC",
    3: "3DES-CBC",
    4: "DES-IV32",
    5: "RC5-CBC",
    6: "IDEA-CBC",
    7: "CAST-CBC",
    8: "BLOWFISH-CBC",
    10: "DES-IV64",
    11: "NULL",
}


def canon_v1_esp_encryption(transform_id: int, key_length: int | None) -> str:
    kl = key_length
    if transform_id in (12,):  # ENCR_AES_CBC
        return f"AES-{kl or 128}-CBC"
    if transform_id == 13:  # ENCR_AES_CTR
        return f"AES-{kl or 128}-CTR"
    if transform_id in (18, 19, 20):  # ENCR_AES_GCM_{8,12,16}
        return f"AES-{kl or 128}-GCM"
    if transform_id in (14, 15, 16):  # ENCR_AES_CCM_{8,12,16}
        return f"AES-{kl or 128}-CCM"
    return _V1_ESP_NAMES.get(transform_id, f"ESP_{transform_id}")


# Quick Mode SA attribute types (RFC 2407 section 4.5)
V1_P2_ATTR_LIFE_TYPE = 1
V1_P2_ATTR_LIFE_DURATION = 2
V1_P2_ATTR_GROUP_DESC = 3
V1_P2_ATTR_ENCAP_MODE = 4
V1_P2_ATTR_AUTH_ALG = 5
V1_P2_ATTR_KEY_LENGTH = 6

# Encapsulation Mode values (RFC 2407 section 4.5 + RFC 3947 NAT-T)
V1_ENCAP_TUNNEL = 1
V1_ENCAP_TRANSPORT = 2
V1_ENCAP_UDP_TUNNEL = 3
V1_ENCAP_UDP_TRANSPORT = 4

# IPSEC AH/ESP Authentication Algorithm (RFC 2407 section 4.5)
_V1_ESP_AUTH_NAMES = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "DES-MAC",
    5: "HMAC-SHA256",
    6: "HMAC-SHA384",
    7: "HMAC-SHA512",
    8: "AES-XCBC",
    9: "AES-CMAC",
}


def canon_v1_esp_integrity(auth_alg: int | None) -> str | None:
    if auth_alg is None:
        return None
    return _V1_ESP_AUTH_NAMES.get(auth_alg, f"AUTH_{auth_alg}")
