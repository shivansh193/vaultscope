import { Toolbar } from "@/components/Toolbar";
import { UploadDrop } from "@/components/UploadDrop";

export default function CapturePage() {
  return (
    <>
      <Toolbar title="Capture" />
      <div className="px-7 py-10">
        <h2 className="max-w-[24ch] text-[length:var(--text-large-title)] font-semibold leading-tight tracking-tight">
          Analyse an IPsec capture
        </h2>
        <p className="mt-3 max-w-[58ch] text-[length:var(--text-body)] text-label-secondary">
          VaultScope reconstructs the IKE handshake, scores the negotiated cryptography against
          fifteen rules, and infers what kind of traffic rode the tunnel from ESP metadata alone.
        </p>
        <div className="mt-8">
          <UploadDrop />
        </div>
      </div>
    </>
  );
}
