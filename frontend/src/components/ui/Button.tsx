import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Spinner } from './Spinner'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'

const VARIANTS: Record<Variant, string> = {
  primary:
    'neu bg-accent text-on-accent hover:bg-accent-hover hover:shadow-[0_0_0_4px_color-mix(in_srgb,var(--color-accent)_20%,transparent)]',
  secondary:
    'neu border border-glass-edge bg-raised text-fg hover:border-line-strong hover:text-accent',
  ghost: 'neu-soft text-fg-muted hover:bg-raised hover:text-fg',
  danger: 'neu border border-bad/60 bg-raised text-bad hover:bg-raised',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  /** Shows a spinner, disables the button and announces the busy state. */
  loading?: boolean
  icon?: ReactNode
}

export function Button({
  variant = 'primary',
  loading = false,
  icon,
  disabled,
  className = '',
  children,
  type = 'button',
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-md px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-60 ${VARIANTS[variant]} ${className}`}
      {...rest}
    >
      {loading ? <Spinner /> : icon}
      {children}
    </button>
  )
}
