import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react'

export interface SectionTab {
  id: string
  label: string
  count?: number
  content: ReactNode
}

/**
 * Splits a long page into tabbed sections. Every panel stays mounted (inactive ones are
 * `hidden`), so live content keeps updating. Arrow keys, Home and End move between tabs.
 * Printing shows every panel.
 */
export function SectionTabs({
  tabs,
  active,
  onChange,
  label,
}: {
  tabs: SectionTab[]
  active: string
  onChange: (id: string) => void
  label: string
}) {
  const base = useId()
  const refs = useRef<(HTMLButtonElement | null)[]>([])

  function onKeyDown(event: KeyboardEvent, index: number) {
    const last = tabs.length - 1
    const next =
      event.key === 'ArrowRight'
        ? index === last
          ? 0
          : index + 1
        : event.key === 'ArrowLeft'
          ? index === 0
            ? last
            : index - 1
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null
    if (next === null) return
    event.preventDefault()
    onChange(tabs[next].id)
    refs.current[next]?.focus()
  }

  return (
    <div className="flex flex-col gap-6">
      <div
        role="tablist"
        aria-label={label}
        className="flex gap-1 overflow-x-auto border-b border-line print:hidden"
      >
        {tabs.map((tab, index) => {
          const selected = tab.id === active
          return (
            <button
              key={tab.id}
              ref={(el) => {
                refs.current[index] = el
              }}
              type="button"
              role="tab"
              id={`${base}-tab-${tab.id}`}
              aria-selected={selected}
              aria-controls={`${base}-panel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(tab.id)}
              onKeyDown={(e) => onKeyDown(e, index)}
              className={`-mb-px inline-flex min-h-11 shrink-0 items-center gap-2 border-b-2 px-4 text-sm font-medium transition-colors ${
                selected
                  ? 'border-accent text-fg'
                  : 'border-transparent text-fg-muted hover:border-line-strong hover:text-fg'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span
                  className={`font-mono text-xs tabular-nums ${selected ? 'text-accent' : 'text-fg-muted'}`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          )
        })}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`${base}-panel-${tab.id}`}
          aria-labelledby={`${base}-tab-${tab.id}`}
          hidden={tab.id !== active}
          className="flex flex-col gap-4 print:!flex"
        >
          {tab.content}
        </div>
      ))}
    </div>
  )
}
