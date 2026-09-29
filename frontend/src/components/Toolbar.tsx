/** Sticky translucent toolbar: the title of wherever you are, plus its actions. */
export function Toolbar({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex min-h-[var(--toolbar-height)] flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-separator bg-[color-mix(in_srgb,var(--ground)_72%,transparent)] px-4 py-2 backdrop-blur-xl md:px-7">
      <h1 className="text-[length:var(--text-headline)] font-semibold tracking-tight">{title}</h1>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </header>
  );
}
