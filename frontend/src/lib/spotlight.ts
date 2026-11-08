/**
 * Pointer spotlight for `.glass` cards: one document listener writes the pointer position
 * into --mx/--my on the card under the pointer (the CSS draws the glow). Skipped for touch-only
 * devices and reduced motion. Purely decorative.
 */
export function startSpotlight(): void {
  if (typeof window.matchMedia !== 'function') return
  if (!window.matchMedia('(hover: hover) and (prefers-reduced-motion: no-preference)').matches) {
    return
  }
  let frame = 0
  let last: HTMLElement | null = null
  document.addEventListener(
    'pointermove',
    (event) => {
      if (frame) return
      frame = requestAnimationFrame(() => {
        frame = 0
        const target = event.target instanceof Element ? event.target : null
        const card = target?.closest<HTMLElement>('.glass') ?? null
        if (last && last !== card) {
          last.style.removeProperty('--mx')
          last.style.removeProperty('--my')
        }
        last = card
        if (!card) return
        const rect = card.getBoundingClientRect()
        card.style.setProperty('--mx', `${event.clientX - rect.left}px`)
        card.style.setProperty('--my', `${event.clientY - rect.top}px`)
      })
    },
    { passive: true },
  )
}
