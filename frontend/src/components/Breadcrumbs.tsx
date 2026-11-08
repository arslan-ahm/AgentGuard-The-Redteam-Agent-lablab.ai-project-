import { ChevronRight } from 'lucide-react'
import { Fragment } from 'react'
import { Link } from 'react-router'

export interface Crumb {
  label: string
  /** Omit on the current page. */
  to?: string
}

/** Where you are: Scans / site / page. The last crumb is the current page. */
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="print:hidden">
      <ol className="flex flex-wrap items-center gap-1 text-sm text-fg-muted">
        {items.map((item, index) => (
          <Fragment key={`${item.label}-${index}`}>
            {index > 0 && (
              <li aria-hidden="true" className="flex">
                <ChevronRight className="size-3.5" />
              </li>
            )}
            <li className="min-w-0">
              {item.to ? (
                <Link
                  to={item.to}
                  className="inline-flex min-h-11 items-center rounded-sm hover:text-fg hover:underline"
                >
                  {item.label}
                </Link>
              ) : (
                <span aria-current="page" className="block max-w-[32ch] truncate text-fg">
                  {item.label}
                </span>
              )}
            </li>
          </Fragment>
        ))}
      </ol>
    </nav>
  )
}
