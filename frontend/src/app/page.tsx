import { Toolbar } from "@/components/Toolbar";
import { RecentCaptures } from "@/components/RecentCaptures";
import { UploadDrop } from "@/components/UploadDrop";

export default function CapturePage() {
  return (
    <>
      <Toolbar title="Capture" />
      <div className="px-4 py-10 md:px-7">
        <h2 className="max-w-[24ch] text-[length:var(--text-large-title)] font-semibold leading-tight tracking-tight">
          Analyse an IPsec capture
        </h2>
        <p className="mt-3 max-w-[58ch] text-[length:var(--text-body)] text-label-secondary">
          VaultScope reconstructs every IKE handshake, scores the negotiated cryptography against a
          CVE-linked rule table, flags attack behaviour across sessions with the exact frames that
          prove it, and infers what kind of traffic rode each tunnel from ESP metadata alone.
        </p>
        <div className="mt-8">
          <UploadDrop />
        </div>
        <RecentCaptures />
      </div>
    </>
  );
}
