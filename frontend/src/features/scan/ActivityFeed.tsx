import {
  Box,
  CircleCheck,
  CircleDot,
  ClipboardList,
  Play,
  ShieldAlert,
  ShieldOff,
  Trash2,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useRef } from 'react'
import type { AuditEvent } from '../../api/contracts'
import { describeEvent, formatTime } from '../../lib/format'

function iconFor(event: AuditEvent): LucideIcon {
  if (event.decision === 'blocked') return event.action === 'sandbox_destroyed' ? Trash2 : ShieldOff
  switch (event.action) {
    case 'sandbox_launched':
      return Box
    case 'sandbox_destroyed':
      return Trash2
    case 'task.started':
      return Play
    case 'task.finished':
      return CircleCheck
    case 'plan.created':
      return ClipboardList
    case 'containment_demo.armed':
      return ShieldAlert
    default:
      return CircleDot
  }
}

/**
 * The scan's audit trail in time order. Blocked actions are marked with icon, color and a
 * "Blocked" label, so the containment moment stands out without relying on color.
 */
export function ActivityFeed({ events, live }: { events: AuditEvent[]; live: boolean }) {
  const scroller = useRef<HTMLDivElement>(null)

  // Follow new events while live, unless the reader has scrolled up.
  useEffect(() => {
    const el = scroller.current
    if (!el || !live) return
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 120) el.scrollTop = el.scrollHeight
  }, [events.length, live])

  if (events.length === 0) {
    return <p className="px-4 py-6 text-sm text-fg-muted">Waiting for the first event…</p>
  }

  return (
    <div ref={scroller} className="max-h-[32rem] overflow-y-auto">
      <ol role="feed" aria-busy={live} aria-label="Scan activity" className="py-2">
        {events.map((event, index) => {
          const Icon = iconFor(event)
          const blocked = event.decision === 'blocked'
          const last = index === events.length - 1
          const { title, detail } = describeEvent(event)
          return (
            <li
              key={`${event.ts}-${index}`}
              role="article"
              aria-label={blocked ? `Blocked: ${title}` : title}
              className={`relative flex animate-feed-in gap-3 px-4 py-2.5 ${blocked ? 'bg-raised' : ''}`}
            >
              {/* Timeline rail: a line through the dots, stopping at the last event. */}
              {!last && (
                <span
                  aria-hidden="true"
                  className="absolute top-9 bottom-0 left-[1.6875rem] w-px bg-line"
                />
              )}
              <span
                aria-hidden="true"
                className={`relative flex size-6 shrink-0 items-center justify-center rounded-full border ${
                  blocked ? 'border-bad bg-bad text-panel' : 'border-line bg-panel text-fg-muted'
                }`}
              >
                <Icon className="size-3.5" />
              </span>
              <div className="min-w-0 flex-1 pt-0.5">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className={`text-sm font-medium ${blocked ? 'text-bad' : 'text-fg'}`}>
                    {title}
                  </span>
                  {blocked && <span className="label-mono text-bad">Blocked</span>}
                </div>
                <p className="mt-0.5 font-mono text-xs break-all text-fg-muted">{detail}</p>
              </div>
              <time
                dateTime={event.ts}
                className="shrink-0 pt-0.5 font-mono text-xs text-fg-muted tabular-nums"
                title={event.ts}
              >
                {formatTime(event.ts)}
              </time>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
