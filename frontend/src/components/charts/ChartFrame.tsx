/** A chart, its title, and the same numbers as a table for anyone who needs them. */
export function ChartFrame({
  title,
  note,
  children,
  table,
}: {
  title: string;
  note?: string;
  children: React.ReactNode;
  table: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-separator bg-surface p-5">
      <h3 className="text-[length:var(--text-headline)] font-semibold tracking-tight">{title}</h3>
      {note && (
        <p className="mt-1 max-w-[52ch] text-[length:var(--text-footnote)] text-label-secondary">
          {note}
        </p>
      )}
      <div className="mt-4">{children}</div>
      <details className="mt-4">
        <summary className="cursor-pointer text-[length:var(--text-caption)] text-label-tertiary hover:text-label-secondary">
          Show the numbers
        </summary>
        <div className="mt-2 overflow-x-auto">{table}</div>
      </details>
    </section>
  );
}

export const cellClass = "py-1 pr-4 text-[length:var(--text-caption)]";
