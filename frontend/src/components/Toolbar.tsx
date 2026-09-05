/** Sticky translucent toolbar: the title of wherever you are, plus its actions. */
export function Toolbar({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex h-[var(--toolbar-height)] items-center justify-between gap-4 border-b border-separator bg-[color-mix(in_srgb,var(--ground)_72%,transparent)] px-7 backdrop-blur-xl">
      <h1 className="text-[length:var(--text-headline)] font-semibold tracking-tight">{title}</h1>
      <div className="flex items-center gap-2">{children}</div>
    </header>
  );
}
