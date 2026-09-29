"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BackendStatus } from "./BackendStatus";

/**
 * macOS source list: the whole console is seven places, so they are all visible.
 * Below the md breakpoint it folds into a top bar that scrolls sideways.
 */
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
      className="fixed inset-x-0 top-0 z-20 flex h-[var(--mobile-bar)] items-center border-b border-separator bg-surface md:inset-x-auto md:inset-y-0 md:left-0 md:h-auto md:w-[var(--sidebar-width)] md:flex-col md:items-stretch md:border-r md:border-b-0"
    >
      <div className="flex shrink-0 items-center gap-2.5 px-4 md:h-[var(--toolbar-height)]">
        <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-accent" />
        <span className="text-[length:var(--text-headline)] font-semibold tracking-tight">
          VaultScope
        </span>
      </div>

      <ul className="flex min-w-0 flex-1 gap-0.5 overflow-x-auto px-2 md:flex-none md:flex-col md:overflow-visible md:py-2">
        {DESTINATIONS.map(({ href, label }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <li key={href}>
              <Link
                href={href}
                aria-current={active ? "page" : undefined}
                className={`block whitespace-nowrap rounded-md px-2.5 py-1.5 text-[length:var(--text-subhead)] transition-colors ${
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

      <div className="mt-auto hidden border-t border-separator p-3 md:block">
        <BackendStatus />
      </div>
    </nav>
  );
}
