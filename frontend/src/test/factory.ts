/** Session builder for tests: canonical defaults, with only the bits that matter overridden. */

import type { Severity, VPNSession } from "@/lib/types";

export function session(
  session_id: string,
  overrides: {
    severity?: Severity;
    score?: number;
    encryption?: string;
    version?: "IKEv1" | "IKEv2";
    initiator?: string;
    responder?: string;
    findings?: number;
  } = {},
): VPNSession {
  const {
    severity = "SAFE",
    score = 100,
    encryption = "AES-256-GCM",
    version = "IKEv2",
    initiator = "10.0.0.1",
    responder = "10.0.0.2",
    findings = severity === "SAFE" ? 0 : 1,
  } = overrides;

  return {
    session_id,
    capture_source: "pcap_upload",
    capture_file: "capture.pcap",
    timestamp: "2026-01-01T00:00:00Z",
    initiator_ip: initiator,
    responder_ip: responder,
    ike: {
      version,
      mode: "tunnel",
      aggressive_mode: version === "IKEv1" && severity === "CRITICAL",
      encryption,
      integrity: "HMAC-SHA2-256",
      prf: "PRF_HMAC_SHA2_256",
      dh_group: severity === "CRITICAL" ? "MODP1024" : "ECP256",
      pfs_status: "enabled",
      auth_method: "RSA",
      ip_version: "IPv4",
      sa_lifetime_sec: 3600,
      vendor: "strongSwan",
      nat_traversal: false,
      fragmented_ike: false,
      capture_complete: true,
      anti_replay: true,
      confidence_source: "parser",
      dpd_status: "unknown",
      dpd_interval_sec: null,
      retransmit_interval_ms: null,
      cert: null,
      msg_sizes: [],
    },
    flow_features: {
      pkt_size_mean: 512,
      pkt_size_std: 64,
      pkt_size_p10: 400,
      pkt_size_p90: 900,
      iat_mean_ms: 20,
      iat_std_ms: 4,
      dir_ratio: 1.1,
      burst_count: 3,
      burst_gap_ratio: 0.2,
      payload_size_var_burst: 12,
      flow_duration_sec: 60,
      pkt_total: 1200,
      rate_pps: 20,
    },
    traffic_prediction: { predicted_type: "Web", confidence: 0.82, model_version: "rf-0.1" },
    security_assessment: {
      risk_score: score,
      overall_severity: severity,
      triggered_rules: findings ? ["R01"] : [],
      findings: Array.from({ length: findings }, (_, i) => ({
        rule_id: `R0${i + 1}`,
        description: "Weak Diffie-Hellman group negotiated",
        severity,
        cve: null,
        standard: "NIST SP 800-77",
        remediation: "crypto ikev2 policy 10\n group 19",
      })),
      threat_matrix: [],
      ai_confidence: 0.82,
    },
    reports: { executive_pdf: null, technical_html: null, json_export: null, cef_export: null },
    packet_refs: [],
  };
}
