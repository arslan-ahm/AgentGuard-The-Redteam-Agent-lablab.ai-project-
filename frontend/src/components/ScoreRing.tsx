import type { Decision } from '../lib/format'
import { DECISION_STYLE } from './decisionStyle'

const SIZES = {
  sm: { box: 40, stroke: 4, text: 'text-xs' },
  lg: { box: 112, stroke: 8, text: 'text-3xl' },
} as const

/**
 * Release score (0–100) as a ring in the verdict colour on a faint accent track. The number is real
 * text in the centre, so the ring is decoration only.
 */
export function ScoreRing({
  score,
  decision,
  size = 'sm',
}: {
  score: number
  decision: Decision
  size?: keyof typeof SIZES
}) {
  const { box, stroke, text } = SIZES[size]
  const radius = (box - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const clamped = Math.max(0, Math.min(100, score))
  const offset = circumference * (1 - clamped / 100)

  return (
    <span
      className="relative inline-flex shrink-0 items-center justify-center"
      style={{ width: box, height: box }}
    >
      <svg aria-hidden="true" width={box} height={box} className="-rotate-90">
        <circle
          cx={box / 2}
          cy={box / 2}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          className="stroke-accent/15"
        />
        <circle
          cx={box / 2}
          cy={box / 2}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={`${DECISION_STYLE[decision].stroke} transition-[stroke-dashoffset] duration-700 ease-out`}
        />
      </svg>
      <span className={`absolute font-semibold text-fg tabular-nums ${text}`}>{score}</span>
    </span>
  )
}
