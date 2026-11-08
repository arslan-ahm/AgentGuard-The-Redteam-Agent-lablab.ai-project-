import { Check, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'

/** Icon button that copies `text`; confirms with a tick and a polite announcement. */
export function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')

  useEffect(() => {
    if (state === 'idle') return
    const timer = setTimeout(() => setState('idle'), 1500)
    return () => clearTimeout(timer)
  }, [state])

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setState('copied')
    } catch {
      setState('failed')
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      title={label}
      className="inline-flex size-11 shrink-0 items-center justify-center neu-soft rounded-md text-fg-muted hover:bg-raised hover:text-accent print:hidden"
    >
      {state === 'copied' ? (
        <Check aria-hidden="true" className="size-4 text-success" />
      ) : (
        <Copy aria-hidden="true" className="size-4" />
      )}
      <span className="sr-only" aria-live="polite">
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : ''}
      </span>
    </button>
  )
}
