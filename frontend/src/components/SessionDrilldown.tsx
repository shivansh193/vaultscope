"use client";

import { AnomalyList } from "@/components/AnomalyList";
import { SEVERITY_COLOR } from "@/lib/severity";
import type { AnomalyEvent, VPNSession } from "@/lib/types";

/** Set by the pipeline when a session's peers carried no ESP to measure. */
export const NO_ESP = "no-esp-observed";

const inferred = (s: VPNSession, value: string) =>
  s.ike.confidence_source === "classifier" && value !== "unknown" ? `${value} (inferred)` : value;

const IKE_FIELDS: [label: string, read: (s: VPNSession) => string][] = [
  ["Version", (s) => s.ike.version + (s.ike.aggressive_mode ? " Aggressive Mode" : "")],
  ["Mode", (s) => s.ike.mode],
  ["Encryption", (s) => inferred(s, s.ike.encryption)],
  ["Integrity", (s) => s.ike.integrity],
  ["PRF", (s) => s.ike.prf],
  ["DH group", (s) => inferred(s, s.ike.dh_group)],
  ["PFS", (s) => s.ike.pfs_status],
  ["Authentication", (s) => s.ike.auth_method ?? "undetermined"],
  ["SA lifetime", (s) => `${s.ike.sa_lifetime_sec} s`],
  ["IP version", (s) => s.ike.ip_version],
  ["NAT traversal", (s) => (s.ike.nat_traversal ? "detected" : "no")],
  ["Anti-replay", (s) => (s.ike.anti_replay ? "on" : "off")],
  ["Vendor", (s) => s.ike.vendor],
  ["First seen", (s) => (s.timestamp ? s.timestamp.replace("T", " ").slice(0, 19) + " UTC" : "unknown")],
  [
    "IKE frames",
    (s) =>
      s.packet_refs.length === 0
        ? "none"
        : s.packet_refs.slice(0, 10).join(", ") + (s.packet_refs.length > 10 ? ", …" : ""),
  ],
];

/**
 * P4-T4. A panel rather than a route: the table stays in view, and a static
 * export never has to enumerate session ids.
 */
export function SessionDrilldown({
  session,
  onClose,
  anomalies = [],
  jobId,
  captureAvailable,
}: {
  session: VPNSession;
  onClose: () => void;
  anomalies?: AnomalyEvent[];
  jobId?: string;
  captureAvailable?: boolean;
}) {
  const { security_assessment: assessment, traffic_prediction: prediction } = session;
  const noEsp = prediction.model_version === NO_ESP;

  return (
    <aside
      data-testid="session-drilldown"
      aria-label={`Session ${session.session_id}`}
      className="fixed inset-0 z-30 flex flex-col overflow-y-auto bg-surface md:static md:inset-auto md:z-auto md:h-full md:w-[420px] md:shrink-0 md:border-l md:border-separator"
    >
      <header className="sticky top-0 flex items-start justify-between gap-3 border-b border-separator bg-surface px-5 py-4">
        <div className="min-w-0">
          <p
            title={session.session_id}
            className="mono truncate text-[length:var(--text-caption)] text-label-tertiary"
          >
            {session.session_id}
          </p>
          <p className="mono mt-1 text-[length:var(--text-subhead)] leading-snug">
            {session.initiator_ip}
            <span aria-hidden className="mx-1 text-label-tertiary">
              →
            </span>
            {session.responder_ip}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close session"
          className="rounded-md px-2 py-1 text-label-secondary hover:bg-surface-raised hover:text-label"
        >
          ✕
        </button>
      </header>

      <div className="flex items-center gap-3 border-b border-separator px-5 py-4">
        <span
          aria-hidden
          className="h-10 w-1 rounded-full"
          style={{ background: SEVERITY_COLOR[assessment.overall_severity] }}
        />
        <div>
          <p className="tabular text-[length:var(--text-title-1)] font-semibold leading-none">
            {assessment.risk_score}
          </p>
          <p className="mt-1 text-[length:var(--text-footnote)] text-label-secondary">
            {assessment.overall_severity} · {assessment.findings.length} finding
            {assessment.findings.length === 1 ? "" : "s"}
          </p>
        </div>
        <div className="ml-auto text-right" data-testid="traffic-prediction">
          {noEsp ? (
            <>
              <p className="text-[length:var(--text-subhead)] text-label-secondary">No ESP seen</p>
              <p className="text-[length:var(--text-footnote)] text-label-tertiary">
                nothing to infer traffic from
              </p>
            </>
          ) : (
            <>
              <p className="text-[length:var(--text-subhead)]">{prediction.predicted_type}</p>
              <p className="text-[length:var(--text-footnote)] text-label-tertiary">
                {Math.round(prediction.confidence * 100)}% · {prediction.model_version}
              </p>
            </>
          )}
        </div>
      </div>

      {!session.ike.capture_complete && (
        <p className="border-b border-separator px-5 py-3 text-[length:var(--text-footnote)] text-medium">
          Partial decode. The capture did not include the full handshake, so any parameter it
          never revealed reads <span className="mono">unknown</span> and is not scored — nothing
          here is a guess passed off as an observation.
        </p>
      )}

      {anomalies.length > 0 && (
        <section className="border-b border-separator px-5 py-4" data-testid="session-anomalies">
          <h3 className="text-[length:var(--text-subhead)] font-semibold">Attack indicators</h3>
          <p className="mt-1 mb-3 text-[length:var(--text-caption)] text-label-tertiary">
            Behaviour across this capture that looks like an attacker, not a misconfiguration.
          </p>
          <AnomalyList
            anomalies={anomalies}
            jobId={jobId}
            captureAvailable={captureAvailable}
            compact={false}
          />
        </section>
      )}

      <section className="border-b border-separator px-5 py-4">
        <h3 className="text-[length:var(--text-subhead)] font-semibold">IKE negotiation</h3>
        <dl className="mt-3 grid grid-cols-[7.5rem_1fr] gap-x-3 gap-y-1.5 text-[length:var(--text-footnote)]">
          {IKE_FIELDS.map(([label, read]) => (
            <div key={label} className="contents">
              <dt className="text-label-secondary">{label}</dt>
              <dd className="mono break-words">{read(session)}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="border-b border-separator px-5 py-4">
        <h3 className="text-[length:var(--text-subhead)] font-semibold">
          {assessment.findings.length === 0 ? "No rule violations" : "Rule violations"}
        </h3>
        {assessment.findings.length === 0 ? (
          <p className="mt-2 text-[length:var(--text-footnote)] text-label-secondary">
            This session passed every rule in the table.
          </p>
        ) : (
          <ul className="mt-3 flex flex-col gap-4">
            {assessment.findings.map((finding) => (
              <li key={finding.rule_id} data-testid="finding">
                <div className="flex items-baseline gap-2">
                  <span
                    className="mono text-[length:var(--text-caption)]"
                    style={{ color: SEVERITY_COLOR[finding.severity] }}
                  >
                    {finding.rule_id}
                  </span>
                  <span className="text-[length:var(--text-footnote)]">{finding.description}</span>
                </div>
                <p className="mt-1 text-[length:var(--text-caption)] text-label-tertiary">
                  {[finding.standard, finding.cve].filter(Boolean).join(" · ")}
                </p>
                {finding.remediation && (
                  <pre
                    data-testid="config-diff"
                    className="mono mt-2 overflow-x-auto rounded-lg bg-ground p-3 text-[length:var(--text-caption)] leading-relaxed text-label"
                  >
                    {finding.remediation}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="px-5 py-4">
        <h3 className="text-[length:var(--text-subhead)] font-semibold">Flow measurements</h3>
        <p className="mt-1 text-[length:var(--text-caption)] text-label-tertiary">
          ESP stays encrypted. The traffic type above is inferred from these numbers alone.
        </p>
        <dl className="mt-3 grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5 text-[length:var(--text-footnote)]">
          {Object.entries(session.flow_features).map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="text-label-secondary">{key.replace(/_/g, " ")}</dt>
              <dd className="mono tabular">
                {typeof value === "number" ? Number(value.toFixed(2)) : value}
              </dd>
            </div>
          ))}
        </dl>
      </section>
    </aside>
  );
}
