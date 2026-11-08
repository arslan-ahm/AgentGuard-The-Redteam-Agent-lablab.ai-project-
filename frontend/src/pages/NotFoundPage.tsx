import { Link } from 'react-router'
import { buttonClasses } from '../components/ui/buttonStyles'

export function NotFoundPage() {
  return (
    <section aria-labelledby="not-found-title" className="py-12">
      <p className="text-sm font-medium text-fg-muted">404</p>
      <h1 id="not-found-title" className="mt-1 text-2xl font-semibold text-fg">
        Page not found
      </h1>
      <p className="mt-2 text-sm text-fg-muted">The page you opened doesn’t exist or has moved.</p>
      <Link to="/" className={buttonClasses('secondary', 'mt-6')}>
        Back to scans
      </Link>
    </section>
  )
}
