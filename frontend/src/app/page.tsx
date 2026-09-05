import { Toolbar } from "@/components/Toolbar";

export default function CapturePage() {
  return (
    <>
      <Toolbar title="Capture" />
      <div className="px-7 py-10">
        <div className="max-w-[54ch]">
          <h2 className="text-[length:var(--text-large-title)] font-semibold leading-tight tracking-tight">
            Analyse an IPsec capture
          </h2>
          <p className="mt-3 text-[length:var(--text-body)] text-label-secondary">
            VaultScope reconstructs the IKE handshake from a pcap, scores the negotiated
            cryptography against fifteen rules, and infers what kind of traffic rode the tunnel
            from ESP metadata alone.
          </p>
          <p className="mt-6 text-[length:var(--text-subhead)] text-label-tertiary">
            Upload arrives in the next build. The sidebar reports whether the backend is
            answering.
          </p>
        </div>
      </div>
    </>
  );
}
