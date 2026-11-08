import { LoaderCircle } from 'lucide-react'

/** Decorative spinner; pair it with visible text or `aria-busy` on the container. */
export function Spinner({ className = 'size-4' }: { className?: string }) {
  return <LoaderCircle aria-hidden="true" className={`animate-spin ${className}`} />
}

/** Full-area loading state with a visible label. */
export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-3 py-12 text-sm text-fg-muted">
      <Spinner />
      {label}
    </div>
  )
}
