import { Link } from 'react-router'

export function NotFoundPage() {
  return (
    <section aria-labelledby="not-found-title" className="py-12">
      <p className="text-sm font-medium text-fg-muted">404</p>
      <h1 id="not-found-title" className="mt-1 text-2xl font-semibold text-fg">
        Page not found
      </h1>
      <p className="mt-2 text-sm text-fg-muted">The page you opened doesn’t exist or has moved.</p>
      <Link
        to="/"
        className="mt-6 inline-flex min-h-11 items-center neu rounded-md border border-glass-edge bg-raised px-4 text-sm font-medium text-fg hover:border-line-strong hover:text-accent"
      >
        Back to scans
      </Link>
    </section>
  )
}
