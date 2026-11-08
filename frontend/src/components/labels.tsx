import {
  Circle,
  CircleCheck,
  CircleDashed,
  CircleX,
  Clock,
  Diamond,
  LoaderCircle,
  ShieldAlert,
  ShieldOff,
  Triangle,
  type LucideIcon,
} from 'lucide-react'
import type { ScanStatus, Severity } from '../api/contracts'
import { DECISION_LABELS, SEVERITY_LABELS, STATUS_LABELS, type Decision } from '../lib/format'
import { DECISION_STYLE } from './decisionStyle'

/**
 * Severity always reads as shape + word + colour, so it survives greyscale printing and colour
 * blindness: critical = filled diamond, high = filled triangle, medium = filled circle,
 * low = outlined circle.
 */
const SEVERITY_STYLE: Record<Severity, { icon: LucideIcon; filled: boolean; tone: string }> = {
  critical: { icon: Diamond, filled: true, tone: 'text-critical' },
  high: { icon: Triangle, filled: true, tone: 'text-high' },
  medium: { icon: Circle, filled: true, tone: 'text-medium' },
  low: { icon: Circle, filled: false, tone: 'text-low' },
}

export function SeverityLabel({ severity }: { severity: Severity }) {
  const { icon: Icon, filled, tone } = SEVERITY_STYLE[severity]
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-sm font-medium whitespace-nowrap ${tone}`}
    >
      <Icon
        aria-hidden="true"
        className="size-3 shrink-0"
        fill={filled ? 'currentColor' : 'none'}
        strokeWidth={filled ? 1.5 : 2.5}
      />
      {SEVERITY_LABELS[severity]}
    </span>
  )
}

/** "Needs manual review" marker: the dashed circle, in neutral grey. */
export function ReviewLabel() {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm font-medium whitespace-nowrap text-fg-muted">
      <CircleDashed aria-hidden="true" className="size-3 shrink-0" strokeWidth={2.5} />
      Manual review
    </span>
  )
}

const STATUS_STYLE: Record<ScanStatus, { icon: LucideIcon; iconTone: string; spin?: boolean }> = {
  queued: { icon: Clock, iconTone: 'text-fg-muted' },
  planning: { icon: LoaderCircle, iconTone: 'text-accent', spin: true },
  running: { icon: LoaderCircle, iconTone: 'text-accent', spin: true },
  verifying: { icon: LoaderCircle, iconTone: 'text-accent', spin: true },
  awaiting_approval: { icon: ShieldAlert, iconTone: 'text-warn' },
  completed: { icon: CircleCheck, iconTone: 'text-success' },
  failed: { icon: CircleX, iconTone: 'text-bad' },
  blocked: { icon: ShieldOff, iconTone: 'text-bad' },
}

/** Scan status: icon in the state colour, label in the text colour. No background. */
export function StatusLabel({ status }: { status: ScanStatus }) {
  const { icon: Icon, iconTone, spin } = STATUS_STYLE[status]
  return (
    <span className="inline-flex items-center gap-1.5 text-sm whitespace-nowrap">
      <Icon
        aria-hidden="true"
        className={`size-3.5 shrink-0 ${iconTone} ${spin ? 'animate-spin' : ''}`}
      />
      <span className="text-fg">{STATUS_LABELS[status]}</span>
    </span>
  )
}

/** Release decision as icon + short label. */
export function DecisionLabel({ decision }: { decision: Decision }) {
  const { icon: Icon, text } = DECISION_STYLE[decision]
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-sm font-medium whitespace-nowrap ${text}`}
    >
      <Icon aria-hidden="true" className="size-4 shrink-0" />
      {DECISION_LABELS[decision]}
    </span>
  )
}
