"use client";

import { useState } from "react";
import { operatorToken, setOperatorToken } from "@/lib/api";

/**
 * Where the operator enters VAULTSCOPE_API_TOKEN. Shown only when the backend
 * has asked for it (a 401) or before an action that always needs it.
 */
export function OperatorToken({ onSaved }: { onSaved?: () => void }) {
  const [value, setValue] = useState(() =>
    typeof window === "undefined" ? "" : operatorToken(),
  );

  return (
    <form
      data-testid="operator-token"
      onSubmit={(e) => {
        e.preventDefault();
        setOperatorToken(value.trim());
        onSaved?.();
      }}
      className="mt-2 flex flex-wrap items-center gap-2 text-[length:var(--text-caption)] text-label-secondary"
    >
      <label className="flex items-center gap-2">
        Operator token
        <input
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="w-40 rounded-md border border-separator bg-surface-raised px-2 py-1 text-label"
        />
      </label>
      <button
        type="submit"
        className="rounded-md border border-separator bg-surface-raised px-2 py-1 text-label hover:bg-surface-control"
      >
        Save
      </button>
    </form>
  );
}
