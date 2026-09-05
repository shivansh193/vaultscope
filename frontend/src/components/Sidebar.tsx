"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BackendStatus } from "./BackendStatus";

/** macOS source list: the whole console is four places, so they are all visible. */
const DESTINATIONS = [
  { href: "/", label: "Capture" },
  { href: "/sessions", label: "Sessions" },
  { href: "/graph", label: "Peers" },
  { href: "/overview", label: "Overview" },
  { href: "/live", label: "Live" },
  { href: "/compare", label: "Compare" },
  { href: "/export", label: "Export" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <nav
      aria-label="Sections"
      className="fixed inset-y-0 left-0 flex w-[var(--sidebar-width)] flex-col border-r border-separator bg-surface"
    >
      <div className="flex h-[var(--toolbar-height)] items-center gap-2.5 px-4">
        <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-accent" />
        <span className="text-[length:var(--text-headline)] font-semibold tracking-tight">
          VaultScope
        </span>
      </div>

      <ul className="flex flex-col gap-0.5 px-2 py-2">
        {DESTINATIONS.map(({ href, label }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <li key={href}>
              <Link
                href={href}
                aria-current={active ? "page" : undefined}
                className={`block rounded-md px-2.5 py-1.5 text-[length:var(--text-subhead)] transition-colors ${
                  active
                    ? "bg-surface-control text-label"
                    : "text-label-secondary hover:bg-surface-raised hover:text-label"
                }`}
              >
                {label}
              </Link>
            </li>
          );
        })}
      </ul>

      <div className="mt-auto border-t border-separator p-3">
        <BackendStatus />
      </div>
    </nav>
  );
}
