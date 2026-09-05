"""Canonical VaultScope data model (product spec, Section 5).

Single source of truth for the whole pipeline: the IKE parser fills ``ike``,
the flow extractor fills ``flow_features``, the classifiers fill
``traffic_prediction``, the rule engine fills ``security_assessment``, and the
report aggregator fills ``reports``. The DB layer, the FastAPI responses, the
JSON/CEF exports and the Jinja2 templates all read these same models -- do not
define a second shape for a session anywhere.
"""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]

# Weighted penalty per severity (spec Section 4, Scoring Model).
SEVERITY_PENALTY: dict[str, int] = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

# Worst-first, so `min(..., key=SEVERITY_ORDER.index)` picks the worst severity.
SEVERITY_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]


class IkeParams(BaseModel):
    """Cryptographic negotiation parameters recovered from the IKE handshake."""

    version: Literal["IKEv1", "IKEv2"] = "IKEv2"
    mode: Literal["tunnel", "transport"] = "tunnel"
    aggressive_mode: bool = False
    encryption: str = "AES-256-GCM"
    integrity: str = "implicit"
    prf: str = "PRF_HMAC_SHA2_256"
    dh_group: str = "ECP256"
    pfs_status: Literal["enabled", "disabled", "unknown"] = "enabled"
    # Spec Section 5 lists PSK | RSA | EAP | XAUTH, but real IKE also negotiates
    # DSS and ECDSA signatures, and an opaque (encrypted) IKE_AUTH leaves the
    # method undetermined -- None. Rules R06/R13 test `eq PSK`, so any other
    # value (or None) is simply "not PSK".
    auth_method: Literal["PSK", "RSA", "DSS", "ECDSA", "EAP", "XAUTH"] | None = "RSA"
    ip_version: Literal["IPv4", "IPv6"] = "IPv4"
    sa_lifetime_sec: int = 3600
    vendor: str = "unknown"
    nat_traversal: bool = False
    fragmented_ike: bool = False
    capture_complete: bool = True
    # Not in spec Section 5's ike block, but rule R15 (anti-replay disabled,
    # RFC 4303 3.4.3) has nothing to evaluate without it. Defaults to the safe
    # value so a parser that cannot determine it never trips the rule.
    anti_replay: bool = True


class FlowFeatures(BaseModel):
    """Metadata-only per-flow statistics -- the Stage 4b classifier's input."""

    pkt_size_mean: float = 0.0
    pkt_size_std: float = 0.0
    pkt_size_p10: float = 0.0
    pkt_size_p90: float = 0.0
    iat_mean_ms: float = 0.0
    iat_std_ms: float = 0.0
    dir_ratio: float = 0.0
    burst_count: int = 0
    burst_gap_ratio: float = 0.0
    payload_size_var_burst: float = 0.0
    flow_duration_sec: float = 0.0
    pkt_total: int = 0
    rate_pps: float = 0.0


class TrafficPrediction(BaseModel):
    """Stage 4b output: traffic type inferred from ESP metadata side-channels."""

    predicted_type: Literal["VoIP", "Video", "Web", "Email", "ICMP", "Chat", "Other"] = "Other"
    confidence: float = 0.0
    model_version: str = "untrained"


class Finding(BaseModel):
    """One triggered security rule, with its vendor-specific remediation."""

    rule_id: str
    description: str
    severity: Severity
    cve: str | None = None
    standard: str = ""
    remediation: str = ""


class ThreatMatrixEntry(BaseModel):
    threat: str
    likelihood: Literal["Low", "Med", "High"]
    impact: Literal["Low", "Med", "High"]


class SecurityAssessment(BaseModel):
    """Stage 4c + Stage 5 output: what is wrong with this session and how bad."""

    risk_score: int = 100
    overall_severity: Severity = "SAFE"
    triggered_rules: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    threat_matrix: list[ThreatMatrixEntry] = Field(default_factory=list)
    ai_confidence: float = 0.0


class Reports(BaseModel):
    """Paths to generated artifacts; None until the report stage runs."""

    executive_pdf: str | None = None
    technical_html: str | None = None
    json_export: str | None = None
    cef_export: str | None = None


class VPNSession(BaseModel):
    """One IPsec VPN session, keyed by its IKE SPI pair."""

    session_id: str
    capture_source: Literal["pcap_upload", "live_nic", "active_probe"] = "pcap_upload"
    capture_file: str | None = None
    timestamp: str = ""
    initiator_ip: str = ""
    responder_ip: str = ""
    ike: IkeParams = Field(default_factory=IkeParams)
    flow_features: FlowFeatures = Field(default_factory=FlowFeatures)
    traffic_prediction: TrafficPrediction = Field(default_factory=TrafficPrediction)
    security_assessment: SecurityAssessment = Field(default_factory=SecurityAssessment)
    reports: Reports = Field(default_factory=Reports)


class AnomalyEvent(BaseModel):
    """Spec Section 5.2 -- a protocol-level anomaly, not a config weakness."""

    anomaly_id: str
    session_id: str
    timestamp: str
    anomaly_type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    description: str
    evidence_pkts: list[int] = Field(default_factory=list)
