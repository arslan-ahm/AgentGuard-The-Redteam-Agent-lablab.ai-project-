import {
  Box,
  CircleCheck,
  ClipboardList,
  RotateCcw,
  ShieldOff,
  Trash2,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { ScoreRing } from '../../components/ScoreRing'
import { DecisionLabel } from '../../components/labels'

interface Step {
  icon: LucideIcon
  title: string
  detail: string
  tag: string
  tone?: 'bad' | 'warn'
}

/** A scripted demo of one scan, mirroring the real event names. Illustration only. */
const STEPS: Step[] = [
  { icon: ClipboardList, title: 'Test plan created', detail: '8 tasks, full audit', tag: 'Plan' },
  { icon: Box, title: 'Sandbox launched', detail: 'fresh, locked-down container', tag: 'Launch' },
  {
    icon: TriangleAlert,
    title: 'Checkout fails',
    detail: 'HTTP 500 with a stack trace',
    tag: 'Fail',
    tone: 'warn',
  },
  {
    icon: ShieldOff,
    title: 'Blocked by policy',
    detail: 'http://169.254.169.254/latest/meta-data/',
    tag: 'Blocked',
    tone: 'bad',
  },
  { icon: Trash2, title: 'Sandbox destroyed', detail: 'nothing left behind', tag: 'Purged' },
]
const STEP_MS = 1100

/** True of every scan (brief 6.4 and 12), not demo numbers. */
const FACTS = [
  { label: 'Isolation', value: 'One box per task' },
  { label: 'Egress', value: 'Private IPs blocked' },
  { label: 'Teardown', value: 'Always' },
]

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : false
}

/**
 * Login-page showcase: a short, self-playing scan (plan, sandbox, finding, the containment
 * block, teardown, score). Plays once, then offers Replay. With reduced motion it shows the
 * finished state straight away. Decorative: hidden from assistive tech, the page says the same
 * in words.
 */
export function ScanShowcase() {
  const total = STEPS.length + 1 // the steps, then the score
  const [shown, setShown] = useState(() => (prefersReducedMotion() ? total : 0))
  const [run, setRun] = useState(0)

  useEffect(() => {
    if (shown >= total) return
    const timer = setTimeout(() => setShown((n) => n + 1), shown === 0 ? 500 : STEP_MS)
    return () => clearTimeout(timer)
  }, [shown, total, run])

  const done = shown >= total

  return (
    <div className="dark-scope flex h-full flex-col justify-center gap-8 bg-canvas bg-[radial-gradient(40rem_30rem_at_85%_15%,var(--color-glow-1),transparent_60%),radial-gradient(35rem_30rem_at_10%_95%,var(--color-glow-2),transparent_60%)] px-10 py-12 text-fg xl:px-16">
      <div className="max-w-md">
        <p className="label-mono text-accent">How a scan runs</p>
        <h2 className="mt-2 text-title font-semibold tracking-tight">
          Real browser tests, sealed in a sandbox.
        </h2>
        <p className="mt-3 text-base text-fg-muted">
          Every finding comes with proof. Anything unsafe is blocked before it leaves the box.
        </p>
      </div>

      <dl className="grid max-w-md grid-cols-3 gap-3">
        {FACTS.map((fact) => (
          <div key={fact.label} className="glass rounded-lg border border-glass-edge px-3 py-2.5">
            <dt className="label-mono text-fg-muted">{fact.label}</dt>
            <dd className="mt-1 text-sm font-medium text-accent">{fact.value}</dd>
          </div>
        ))}
      </dl>

      <div className="glass max-w-md rounded-lg border border-glass-edge">
        <div
          aria-hidden="true"
          className="flex items-center justify-between border-b border-line px-4 py-3"
        >
          <span className="font-mono text-sm text-fg">demo-store.example</span>
          <span className="inline-flex items-center gap-2 text-xs text-fg-muted">
            <span
              className={`size-1.5 rounded-full ${done ? 'bg-fg-muted' : 'animate-pulse bg-success'}`}
            />
            {done ? 'Finished' : 'Live'}
          </span>
        </div>

        <ol aria-hidden="true" className="flex min-h-[19rem] flex-col gap-1 p-2">
          {STEPS.slice(0, shown).map((step, index) => {
            const Icon = step.icon
            const bad = step.tone === 'bad'
            return (
              <li
                key={`${run}-${step.title}`}
                className={`flex animate-feed-in items-start gap-3 rounded-md px-3 py-2 ${
                  bad ? 'bg-raised' : ''
                }`}
              >
                <span
                  className={`mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border ${
                    bad
                      ? 'border-bad bg-bad text-canvas'
                      : step.tone === 'warn'
                        ? 'border-warn/50 text-warn'
                        : 'border-line text-fg-muted'
                  }`}
                >
                  <Icon className="size-3.5" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className={`block text-sm font-medium ${bad ? 'text-bad' : 'text-fg'}`}>
                    {step.title}
                    {index === STEPS.length - 1 && (
                      <CircleCheck className="ml-1.5 inline size-3.5 align-[-2px] text-success" />
                    )}
                  </span>
                  <span className="block truncate font-mono text-xs text-fg-muted">
                    {step.detail}
                  </span>
                </span>
                <span
                  className={`label-mono ml-auto shrink-0 ${
                    bad
                      ? 'border-bad/50 text-bad'
                      : step.tone === 'warn'
                        ? 'border-warn/50 text-warn'
                        : 'border-line text-fg-muted'
                  }`}
                >
                  {step.tag}
                </span>
              </li>
            )
          })}
        </ol>

        <div className="flex min-h-20 items-center justify-between gap-4 border-t border-line px-4 py-3">
          {done ? (
            <span key={run} aria-hidden="true" className="flex animate-feed-in items-center gap-3">
              <ScoreRing score={60} decision="fixFirst" />
              <DecisionLabel decision="fixFirst" />
            </span>
          ) : (
            <span aria-hidden="true" className="text-sm text-fg-muted">
              Scoring when the tests finish…
            </span>
          )}
          {done && (
            <button
              type="button"
              aria-label="Replay the scan preview"
              onClick={() => {
                setShown(0)
                setRun((r) => r + 1)
              }}
              className="inline-flex min-h-11 items-center gap-2 rounded-md px-3 text-sm text-fg-muted transition-colors hover:bg-raised hover:text-fg"
            >
              <RotateCcw aria-hidden="true" className="size-4" />
              Replay
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
