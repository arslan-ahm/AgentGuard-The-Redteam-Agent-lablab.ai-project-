import { Moon, Sun } from 'lucide-react'
import { useState } from 'react'
import { applyTheme, currentTheme, type Theme } from '../lib/theme'

/** Light / dark switch. Dark is the default. */
export function ThemeToggle({ className = '' }: { className?: string }) {
  const [theme, setTheme] = useState<Theme>(currentTheme)
  const next: Theme = theme === 'dark' ? 'light' : 'dark'
  const Icon = theme === 'dark' ? Sun : Moon

  return (
    <button
      type="button"
      onClick={() => {
        applyTheme(next)
        setTheme(next)
      }}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className={`inline-flex size-11 items-center justify-center neu-soft rounded-md text-fg-muted hover:bg-raised hover:text-accent ${className}`}
    >
      <Icon aria-hidden="true" className="size-4" />
    </button>
  )
}
