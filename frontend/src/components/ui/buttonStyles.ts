export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'neu bg-accent text-on-accent hover:bg-accent-hover hover:shadow-[0_0_0_4px_color-mix(in_srgb,var(--color-accent)_20%,transparent)]',
  secondary:
    'neu border border-glass-edge bg-raised text-fg hover:border-line-strong hover:text-accent',
  ghost: 'neu-soft text-fg-muted hover:bg-raised hover:text-fg',
  danger: 'neu border border-bad/60 bg-raised text-bad hover:bg-raised',
}

/**
 * Button look as a class string, shared by `<Button>` and by links that act as buttons
 * (`<Link className={buttonClasses('primary')}>`), so both stay identical.
 */
export function buttonClasses(variant: ButtonVariant = 'primary', extra = ''): string {
  return `inline-flex min-h-11 items-center justify-center gap-2 rounded-md px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-60 ${VARIANTS[variant]} ${extra}`.trim()
}
