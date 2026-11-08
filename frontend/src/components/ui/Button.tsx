import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { buttonClasses, type ButtonVariant } from './buttonStyles'
import { Spinner } from './Spinner'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
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
      className={buttonClasses(variant, className)}
      {...rest}
    >
      {loading ? <Spinner /> : icon}
      {children}
    </button>
  )
}
