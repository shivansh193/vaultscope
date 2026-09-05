"""Extended IKE signals: Dead Peer Detection, retransmission timing, peer cert.

Kept out of the core parse path -- these are best-effort enrichments that feed
extra rules / fingerprints, not the crypto contract.
"""

from __future__ import annotations

import statistics
from datetime import UTC, datetime

from core.models import CertInfo

# Vendor ID payloads that announce RFC 3706 Dead Peer Detection support.
_DPD_VID_PREFIXES = (
    "afcad71368a1f1c96b8696fc77570100",  # DPD v1.0
    "afcad71368a1f1c96b8696fc7757",  # tolerate a shorter/altered suffix
)

# CERT payload types: IKEv2 = 37, IKEv1 = 6
_CERT_PAYLOAD_TYPES = (37, 6)
# CERT encoding value 4 = X.509 Certificate - Signature (RFC 7296 3.6)
_CERT_ENC_X509_SIG = 4


def dpd_from_messages(messages) -> tuple[str, int | None]:
    """(dpd_status, interval_sec). "enabled" when a peer announces DPD support:
    the RFC 3706 Vendor ID for IKEv1, or an empty INFORMATIONAL liveness
    exchange for IKEv2. "unknown" when the capture never gets that far."""
    vids = [
        p.raw.hex().lower()
        for m in messages
        for p in m.all_payloads()
        if p.type in (43, 13)  # Vendor ID: v2 / v1
    ]
    if any(v.startswith(pfx) for v in vids for pfx in _DPD_VID_PREFIXES):
        return "enabled", None

    # IKEv2: an INFORMATIONAL exchange (type 37) with no payloads is a keepalive
    for m in messages:
        if getattr(m, "is_ikev2", False) and m.exchange_type == 37 and not m.payloads:
            return "enabled", None
    return "unknown", None


def retransmit_interval_ms(ike_times: list[tuple[tuple, float]] | None) -> int | None:
    """Median gap (ms) between identical IKE messages -- retransmissions.

    ``ike_times`` is ``[((exchange_type, message_id, is_response), epoch_secs), ...]``.
    Returns None when fewer than two retransmits (of any single message) exist.
    Cisco retransmits at ~10 s, strongSwan at ~3 s.
    """
    if not ike_times:
        return None
    seen: dict[tuple, list[float]] = {}
    for key, t in ike_times:
        seen.setdefault(key, []).append(t)
    gaps: list[float] = []
    for times in seen.values():
        times.sort()
        gaps.extend(
            times[i] - times[i - 1] for i in range(1, len(times)) if times[i] > times[i - 1]
        )
    if len(gaps) < 2:
        return None
    return int(round(statistics.median(gaps) * 1000))


def cert_from_messages(messages) -> CertInfo | None:
    """Parse the first X.509 CERT payload found in IKE_AUTH, if any."""
    for m in messages:
        for p in m.all_payloads():
            if p.type not in _CERT_PAYLOAD_TYPES or len(p.raw) < 2:
                continue
            enc, der = p.raw[0], p.raw[1:]
            if enc != _CERT_ENC_X509_SIG or not der:
                continue
            info = _parse_x509(der)
            if info is not None:
                return info
    return None


def _parse_x509(der: bytes) -> CertInfo | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError:  # pragma: no cover - cryptography is a hard dep
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    key = cert.public_key()
    key_bits = getattr(key, "key_size", None)
    if key_bits is None and isinstance(key, ec.EllipticCurvePublicKey):
        key_bits = key.curve.key_size
    _ = rsa  # imported for the isinstance vocabulary / future use

    not_after = cert.not_valid_after_utc
    return CertInfo(
        subject=cert.subject.rfc4514_string()[:200],
        issuer=cert.issuer.rfc4514_string()[:200],
        not_after=not_after.isoformat(),
        key_bits=key_bits,
        sig_algorithm=(cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""),
        expired=not_after < datetime.now(UTC),
        self_signed=cert.subject == cert.issuer,
    )
