import { CircleCheck, OctagonX, TriangleAlert, type LucideIcon } from 'lucide-react'
import type { Decision } from '../lib/format'

/** Verdict colours (brief 5.10): block = bad, fix first = warn, safe = success. */
export const DECISION_STYLE: Record<
  Decision,
  { icon: LucideIcon; text: string; soft: string; border: string; stroke: string }
> = {
  block: {
    icon: OctagonX,
    text: 'text-bad',
    soft: 'glass',
    border: 'border-bad',
    stroke: 'stroke-bad',
  },
  fixFirst: {
    icon: TriangleAlert,
    text: 'text-warn',
    soft: 'glass',
    border: 'border-warn',
    stroke: 'stroke-warn',
  },
  safe: {
    icon: CircleCheck,
    text: 'text-success',
    soft: 'glass',
    border: 'border-success',
    stroke: 'stroke-success',
  },
}
