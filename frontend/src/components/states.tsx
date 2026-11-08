import { RotateCw, type LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { errorText } from '../lib/errors'
import { Button } from './ui/Button'

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-lg border border-bad/40 bg-raised p-6">
      <p className="font-medium text-fg">Couldn’t load this page</p>
      <p className="mt-1 text-sm text-fg-muted">{errorText(error)}</p>
      {onRetry && (
        <Button
          variant="secondary"
          className="mt-4"
          onClick={onRetry}
          icon={<RotateCw aria-hidden="true" className="size-4" />}
        >
          Try again
        </Button>
      )}
    </div>
  )
}

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
}: {
  icon: LucideIcon
  title: string
  children?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg glass border border-dashed border-line-strong p-8">
      <Icon aria-hidden="true" className="size-6 text-accent" />
      <p className="font-medium text-fg">{title}</p>
      {children && <div className="max-w-prose text-sm text-fg-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  eyebrow?: ReactNode
}) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow && <div className="mb-2 text-sm text-fg-muted">{eyebrow}</div>}
        <h1 className="text-title font-semibold tracking-tight break-words text-fg">{title}</h1>
        {description && <div className="mt-1 text-sm text-fg-muted">{description}</div>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </div>
  )
}
