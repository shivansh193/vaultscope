"""The ``VPNSession`` record produced by Stage 2.

Field set and value vocabulary follow the product spec:
  * Section 4, "Stage 2 - IKE Parser", "Output - VPNSession Object"
  * Section 5.1, "Core Session Record (DB schema)" -> the ``ike`` sub-object

Downstream consumers (Stage 4a classifier, Stage 4c rule engine, Stage 5
report aggregator) depend on these names, so treat the schema as a contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

PfsStatus = Literal["enabled", "disabled", "unknown"]
IkeMode = Literal["tunnel", "transport"]
ConfidenceSource = Literal["parser", "classifier"]


@dataclass
class VPNSession:
    """One reconstructed IKE security association.

    ``*_status`` / optional fields are ``None`` or ``"unknown"`` when the
    capture did not contain enough to decide -- never a guessed default. The
    rule engine (R10, PFS) relies on ``"unknown"`` not being penalised.
    """

    session_id: str
    ike_version: Literal["IKEv1", "IKEv2"] = "IKEv2"
    mode: IkeMode = "tunnel"
    aggressive_mode: bool = False

    encryption: str | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: str | None = None
    pfs_status: PfsStatus = "unknown"
    auth_method: str | None = None

    ip_version: Literal["IPv4", "IPv6"] | None = None
    sa_lifetime_sec: int | None = None
    vendor: str = "unknown"

    nat_traversal: bool = False
    fragmented_ike: bool = False
    capture_complete: bool = False

    # context / provenance (not part of the 5.1 ike sub-object)
    initiator_ip: str | None = None
    responder_ip: str | None = None
    confidence_source: ConfidenceSource = "parser"
    vendor_ids: list[str] = field(default_factory=list)  # hex of each VID payload
    notify_types: list[int] = field(default_factory=list)  # observed notify msg types

    def to_ike_dict(self) -> dict[str, Any]:
        """The ``ike`` sub-object exactly as specified in spec Section 5.1."""
        return {
            "version": self.ike_version,
            "mode": self.mode,
            "aggressive_mode": self.aggressive_mode,
            "encryption": self.encryption,
            "integrity": self.integrity,
            "prf": self.prf,
            "dh_group": self.dh_group,
            "pfs_status": self.pfs_status,
            "auth_method": self.auth_method,
            "ip_version": self.ip_version,
            "sa_lifetime_sec": self.sa_lifetime_sec,
            "vendor": self.vendor,
            "nat_traversal": self.nat_traversal,
            "fragmented_ike": self.fragmented_ike,
            "capture_complete": self.capture_complete,
        }

    def to_dict(self) -> dict[str, Any]:
        """Full flat dict of every field (superset of ``to_ike_dict``)."""
        return asdict(self)
