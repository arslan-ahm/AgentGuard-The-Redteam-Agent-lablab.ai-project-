import { useId, type InputHTMLAttributes, type ReactNode } from 'react'

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  hint?: string
  error?: string | null
  /** Decorative icon inside the field, on the left. */
  icon?: ReactNode
  /** Interactive control inside the field, on the right (e.g. show password). */
  trailing?: ReactNode
}

/** Labelled input with hint and error text wired to `aria-describedby`. */
export function TextField({
  label,
  hint,
  error,
  icon,
  trailing,
  id,
  className = '',
  ...rest
}: TextFieldProps) {
  const autoId = useId()
  const inputId = id ?? autoId
  const hintId = hint ? `${inputId}-hint` : undefined
  const errorId = error ? `${inputId}-error` : undefined
  const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined

  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={inputId} className="label-mono text-fg-muted">
        {label}
      </label>
      <div className="relative">
        {icon && (
          <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-fg-muted">
            {icon}
          </span>
        )}
        <input
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={`min-h-11 w-full rounded-md border border-line-strong bg-canvas/60 text-base shadow-neu-inset transition-[border-color,box-shadow] focus:border-accent text-fg placeholder:text-fg-muted hover:border-fg-muted aria-invalid:border-bad sm:text-sm ${icon ? 'pl-10' : 'pl-3'} ${trailing ? 'pr-12' : 'pr-3'}`}
          {...rest}
        />
        {trailing && (
          <span className="absolute inset-y-0 right-0 flex items-center">{trailing}</span>
        )}
      </div>
      {hint && (
        <p id={hintId} className="text-xs text-fg-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-sm text-bad">
          {error}
        </p>
      )}
    </div>
  )
}
