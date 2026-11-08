import { Check } from 'lucide-react'
import type { ScanStatus } from '../../api/contracts'
import { FINAL_STATUSES as FINAL } from '../../lib/format'
import type { ScanDetail } from '../../api/schemas'
import type { Connection } from '../../lib/useScanEvents'

const STAGES = [
  { key: 'queued', label: 'Queued' },
  { key: 'planning', label: 'Planning' },
  { key: 'running', label: 'Running tests' },
  { key: 'verifying', label: 'Verifying' },
  { key: 'decision', label: 'Decision' },
] as const

function stageIndex(status: ScanStatus): number {
  switch (status) {
    case 'queued':
      return 0
    case 'planning':
      return 1
    case 'running':
      return 2
    case 'verifying':
      return 3
    default:
      return 4
  }
}

const CONNECTION_TEXT: Record<Connection, string> = {
  connecting: 'Connecting…',
  live: 'Live',
  reconnecting: 'Reconnecting…',
  closed: 'Finished',
  error: 'Disconnected',
}

export function ConnectionStatus({ connection }: { connection: Connection }) {
  const color =
    connection === 'live'
      ? 'bg-success'
      : connection === 'error'
        ? 'bg-bad'
        : connection === 'closed'
          ? 'bg-fg-muted'
          : 'bg-warn'
  return (
    <span className="inline-flex items-center gap-2 text-sm text-fg-muted" aria-live="polite">
      <span aria-hidden="true" className={`size-2 rounded-full ${color}`} />
      {CONNECTION_TEXT[connection]}
    </span>
  )
}

/** Stage stepper + task progress bar for one scan. */
export function ScanProgress({ scan }: { scan: ScanDetail }) {
  const current = stageIndex(scan.status)
  const stopped = scan.status === 'failed' || scan.status === 'blocked'
  const { tasks_done: done, tasks_total: total } = scan.progress
  const fraction = total > 0 ? done / total : 0
  const moving = !FINAL.has(scan.status) && done < total

  return (
    <div className="flex flex-col gap-5">
      <ol className="grid grid-cols-5 gap-2" aria-label="Scan stages">
        {STAGES.map((stage, index) => {
          const complete = index < current || (index === current && index === 4 && !stopped)
          const active = index === current && !complete
          return (
            <li key={stage.key} className="flex flex-col gap-2">
              <span
                aria-hidden="true"
                className={`h-1 rounded-full ${
                  complete
                    ? 'bg-accent'
                    : active
                      ? stopped
                        ? 'bg-bad'
                        : 'bg-accent/50'
                      : 'bg-line'
                }`}
              />
              <span
                className={`flex items-center gap-1 text-xs sm:text-sm ${
                  complete || active ? 'text-fg' : 'text-fg-muted'
                }`}
              >
                {complete && <Check aria-hidden="true" className="hidden size-3.5 sm:block" />}
                {stage.label}
                <span className="sr-only">
                  {complete ? ' (done)' : active ? ' (current)' : ' (pending)'}
                </span>
              </span>
            </li>
          )
        })}
      </ol>

      {total > 0 && (
        <div className="flex flex-col gap-2">
          <div className="flex items-baseline justify-between text-sm">
            <span className="text-fg-muted">Tasks</span>
            <span className="text-fg tabular-nums">
              {done} of {total}
            </span>
          </div>
          <div
            role="progressbar"
            aria-label="Tasks completed"
            aria-valuemin={0}
            aria-valuemax={total}
            aria-valuenow={done}
            className="relative h-2 overflow-hidden rounded-full bg-raised"
          >
            {/* scaleX instead of width so the fill animates on the compositor. */}
            <div
              className="absolute inset-0 origin-left rounded-full bg-accent transition-transform duration-500 ease-out"
              style={{ transform: `scaleX(${fraction})` }}
            />
            {moving && (
              <div
                aria-hidden="true"
                className="absolute inset-0 animate-shimmer bg-linear-to-r from-transparent via-panel/40 to-transparent"
              />
            )}
          </div>
        </div>
      )}
    </div>
  )
}
