import type { ReactNode } from 'react'

/**
 * Two-column page body: content on the left, a sticky summary panel on the right (from xl up).
 * Below xl the panel stacks; `asideFirst` puts it above the content on small screens so the
 * key numbers are seen first. Printing always uses one column.
 */
export function SplitLayout({
  children,
  aside,
  asideLabel,
  asideFirst = false,
}: {
  children: ReactNode
  aside: ReactNode
  asideLabel: string
  asideFirst?: boolean
}) {
  return (
    <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_20rem] xl:items-start print:block">
      <div className="flex min-w-0 flex-col gap-8">{children}</div>
      <aside
        aria-label={asideLabel}
        className={`flex flex-col gap-4 xl:sticky xl:top-8 ${asideFirst ? 'max-xl:order-first' : ''} print:mt-8`}
      >
        {aside}
      </aside>
    </div>
  )
}

/** A titled glass card for the summary panel. */
export function AsideCard({
  title,
  children,
  className = '',
}: {
  title: string
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`glass rounded-lg border border-glass-edge p-5 ${className}`}>
      <h2 className="label-mono text-fg-muted">{title}</h2>
      <div className="mt-3">{children}</div>
    </section>
  )
}
