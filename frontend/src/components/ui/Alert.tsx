import { CircleAlert, CircleCheck, Info, ShieldAlert } from 'lucide-react'
import type { ReactNode } from 'react'

type Tone = 'error' | 'warning' | 'success' | 'info'

const TONES: Record<Tone, { icon: typeof Info; className: string; label: string }> = {
  error: { icon: CircleAlert, className: 'border-bad/40 bg-raised text-bad', label: 'Error' },
  warning: {
    icon: ShieldAlert,
    className: 'border-warn/40 bg-raised text-warn',
    label: 'Warning',
  },
  success: {
    icon: CircleCheck,
    className: 'border-success/40 bg-raised text-success',
    label: 'Success',
  },
  info: { icon: Info, className: 'border-accent/30 bg-raised text-accent', label: 'Note' },
}

interface AlertProps {
  tone?: Tone
  title?: string
  children?: ReactNode
  className?: string
}

/** Inline message with icon + label + color, so meaning never depends on color alone. */
export function Alert({ tone = 'info', title, children, className = '' }: AlertProps) {
  const { icon: Icon, className: toneClass, label } = TONES[tone]
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      className={`flex gap-3 rounded-md border p-3 text-sm ${toneClass} ${className}`}
    >
      <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <div className="text-fg">
        <p className="font-medium">
          <span className="sr-only">{label}: </span>
          {title}
        </p>
        {children && <div className="mt-1 text-fg-muted">{children}</div>}
      </div>
    </div>
  )
}
