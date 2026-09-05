/**
 * Mirror of core/models.py (product spec Section 5).
 *
 * The canonical session shape is defined once, in Python. This file is the
 * TypeScript view of it -- keep the field names and nesting identical, and
 * never add a field here that the backend does not send.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"];

export interface CertInfo {
  subject: string;
  issuer: string;
  not_after: string;
  key_bits: number | null;
  sig_algorithm: string;
  expired: boolean;
  self_signed: boolean;
}

export interface IkeParams {
  version: "IKEv1" | "IKEv2";
  mode: "tunnel" | "transport";
  aggressive_mode: boolean;
  encryption: string;
  integrity: string;
  prf: string;
  dh_group: string;
  pfs_status: "enabled" | "disabled" | "unknown";
  auth_method: "PSK" | "RSA" | "DSS" | "ECDSA" | "EAP" | "XAUTH" | null;
  ip_version: "IPv4" | "IPv6";
  sa_lifetime_sec: number;
  vendor: string;
  nat_traversal: boolean;
  fragmented_ike: boolean;
  capture_complete: boolean;
  anti_replay: boolean;
  confidence_source: "parser" | "classifier";
  dpd_status: "enabled" | "disabled" | "unknown";
  dpd_interval_sec: number | null;
  retransmit_interval_ms: number | null;
  cert: CertInfo | null;
  msg_sizes: number[];
}

export interface FlowFeatures {
  pkt_size_mean: number;
  pkt_size_std: number;
  pkt_size_p10: number;
  pkt_size_p90: number;
  iat_mean_ms: number;
  iat_std_ms: number;
  dir_ratio: number;
  burst_count: number;
  burst_gap_ratio: number;
  payload_size_var_burst: number;
  flow_duration_sec: number;
  pkt_total: number;
  rate_pps: number;
}

export type TrafficType = "VoIP" | "Video" | "Web" | "Email" | "ICMP" | "Chat" | "Other";

export interface TrafficPrediction {
  predicted_type: TrafficType;
  confidence: number;
  model_version: string;
}

export interface Finding {
  rule_id: string;
  description: string;
  severity: Severity;
  cve: string | null;
  standard: string;
  remediation: string;
}

export interface ThreatMatrixEntry {
  threat: string;
  likelihood: "Low" | "Med" | "High";
  impact: "Low" | "Med" | "High";
}

export interface SecurityAssessment {
  risk_score: number;
  overall_severity: Severity;
  triggered_rules: string[];
  findings: Finding[];
  threat_matrix: ThreatMatrixEntry[];
  ai_confidence: number;
}

export interface Reports {
  executive_pdf: string | null;
  technical_html: string | null;
  json_export: string | null;
  cef_export: string | null;
}

export interface VPNSession {
  session_id: string;
  capture_source: "pcap_upload" | "live_nic" | "active_probe";
  capture_file: string | null;
  timestamp: string;
  initiator_ip: string;
  responder_ip: string;
  ike: IkeParams;
  flow_features: FlowFeatures;
  traffic_prediction: TrafficPrediction;
  security_assessment: SecurityAssessment;
  reports: Reports;
  packet_refs: number[];
}

/** Stage 4b evaluation artifacts from GET /model/metrics ({} until trained). */
export interface ModelMetrics {
  model_version?: string;
  algo?: string;
  source?: string;
  accuracy?: number;
  f1_macro?: number;
  per_class?: Record<string, { precision: number; recall: number; "f1-score": number }>;
  feature_importance?: Record<string, number>;
  note?: string;
}

export interface AnomalyEvent {
  anomaly_id: string;
  session_id: string;
  timestamp: string;
  anomaly_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
  evidence_pkts: number[];
}

export interface Health {
  status: string;
  version: string;
  parser_available: boolean;
}

export interface IngestResult {
  job_id: string;
  session_count: number;
  fixture_mode: boolean;
}

/** A session both captures hold, whose assessment got worse. */
export interface DegradedSession {
  session_id: string;
  base: VPNSession;
  compare: VPNSession;
  base_score: number;
  compare_score: number;
  base_severity: Severity;
  compare_severity: Severity;
}

export interface SessionDiff {
  added: VPNSession[];
  removed: VPNSession[];
  degraded: DegradedSession[];
}
