"use client";

import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import { ingest } from "@/lib/api";
import { rememberJob } from "@/lib/job";

type State =
  | { kind: "idle" }
  | { kind: "uploading"; name: string }
  | { kind: "failed"; why: string };

/** P4-T2: drop a pcap, watch it analyse, land on the sessions it produced. */
export function UploadDrop() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [state, setState] = useState<State>({ kind: "idle" });
  const [over, setOver] = useState(false);

  async function analyse(file: File) {
    setState({ kind: "uploading", name: file.name });
    try {
      const result = await ingest(file);
      rememberJob({
        job_id: result.job_id,
        capture_file: file.name,
        session_count: result.session_count,
        fixture_mode: result.fixture_mode,
      });
      router.push("/sessions");
    } catch (error) {
      setState({ kind: "failed", why: (error as Error).message });
    }
  }

  const busy = state.kind === "uploading";

  return (
    <div className="max-w-[62ch]">
      <div
        data-testid="pcap-drop"
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          const file = e.dataTransfer.files[0];
          if (file) void analyse(file);
        }}
        className={`rounded-2xl border border-dashed p-12 text-center transition-colors ${
          over ? "border-accent bg-[color-mix(in_srgb,var(--accent)_10%,transparent)]" : "border-separator bg-surface"
        }`}
      >
        <p className="text-[length:var(--text-title-3)] font-semibold tracking-tight">
          Drop a capture here
        </p>
        <p className="mx-auto mt-2 max-w-[40ch] text-[length:var(--text-subhead)] text-label-secondary">
          A pcap or pcapng containing the IKE negotiation on UDP 500 or 4500. ESP payloads stay
          encrypted — nothing is decrypted, only measured.
        </p>

        <button
          type="button"
          disabled={busy}
          onClick={() => inputRef.current?.click()}
          className="mt-6 rounded-lg bg-accent px-4 py-2 text-[length:var(--text-subhead)] font-medium text-white transition-colors hover:bg-[var(--accent-pressed)] disabled:opacity-40"
        >
          {busy ? "Analysing" : "Choose a capture"}
        </button>

        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="sr-only"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void analyse(file);
          }}
        />
      </div>

      {busy && (
        <div data-testid="upload-progress" role="status" className="mt-5">
          <div className="flex items-baseline justify-between text-[length:var(--text-footnote)]">
            <span className="text-label-secondary">Reconstructing handshakes</span>
            <span className="mono text-label-tertiary">{state.name}</span>
          </div>
          <div className="mt-2 h-1 overflow-hidden rounded-full bg-surface-raised">
            {/* Indeterminate: the backend analyses in one pass and reports no progress. */}
            <div className="h-full w-1/3 animate-[slide_1.1s_ease-in-out_infinite] rounded-full bg-accent" />
          </div>
        </div>
      )}

      {state.kind === "failed" && (
        <p role="alert" className="mt-5 text-[length:var(--text-subhead)] text-critical">
          That capture could not be analysed. {state.why}
        </p>
      )}

      <style>{`@keyframes slide { 0% { transform: translateX(-100%) } 100% { transform: translateX(300%) } }`}</style>
    </div>
  );
}
