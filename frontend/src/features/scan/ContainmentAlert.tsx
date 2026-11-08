import { CircleCheck, ShieldOff, Trash2 } from 'lucide-react'
import type { AuditEvent } from '../../api/contracts'
import { formatTime, isPolicyBlock } from '../../lib/format'

/**
 * The containment moment (brief 6.1): every action the policy blocked during the scan, with
 * whether its sandbox was destroyed. Renders nothing when nothing was blocked.
 */
export function ContainmentAlert({ events }: { events: AuditEvent[] }) {
  const blocks = events.filter(isPolicyBlock)
  if (blocks.length === 0) return null

  return (
    <section
      role="alert"
      aria-labelledby="containment-title"
      className="animate-alert-pulse overflow-hidden rounded-lg border border-bad/40 bg-raised"
    >
      <div className="flex items-center gap-3 px-5 pt-5">
        <ShieldOff aria-hidden="true" className="size-6 shrink-0 text-bad" />
        <h2 id="containment-title" className="text-lg font-semibold text-bad">
          Blocked by policy
        </h2>
      </div>
      <ul className="flex flex-col divide-y divide-bad/20 px-5">
        {blocks.map((block, index) => {
          const destroyed = events.find(
            (e) =>
              e.action === 'sandbox_destroyed' && e.task_id === block.task_id && e.ts >= block.ts,
          )
          return (
            <li key={`${block.ts}-${index}`} className="flex flex-col gap-3 py-4">
              <div className="flex flex-col gap-1">
                <p className="font-mono text-base break-all text-fg">{block.target}</p>
                <p className="text-sm text-fg">
                  {block.reason}
                  <span className="text-fg-muted tabular-nums"> at {formatTime(block.ts)}</span>
                </p>
              </div>
              <p
                className={`flex items-center gap-2 text-sm font-medium ${
                  destroyed ? 'text-fg' : 'text-fg-muted'
                }`}
              >
                {destroyed ? (
                  <CircleCheck aria-hidden="true" className="size-4 text-success" />
                ) : (
                  <Trash2 aria-hidden="true" className="size-4" />
                )}
                {destroyed
                  ? `Sandbox destroyed at ${formatTime(destroyed.ts)}`
                  : 'Destroying sandbox…'}
              </p>
            </li>
          )
        })}
      </ul>
      <p className="border-t border-bad/20 px-5 py-3 text-xs text-fg-muted">
        The blocked address was never contacted. Every blocked action is written to the
        tamper-evident audit log.
      </p>
    </section>
  )
}
