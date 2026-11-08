import { DECISION_STYLE } from '../../components/decisionStyle'
import { ScoreRing } from '../../components/ScoreRing'
import { DECISION_LABELS, type Decision } from '../../lib/format'

/**
 * Release decision (brief 5.10 / 6.8): the most prominent element of the report. Verdict colour
 * band, icon, verdict, full recommendation and the score ring.
 */
export function DecisionBanner({
  decision,
  score,
  recommendation,
}: {
  decision: Decision
  score: number
  recommendation: string | null | undefined
}) {
  const { icon: Icon, border, text, soft } = DECISION_STYLE[decision]
  return (
    <section
      aria-label="Release decision"
      className={`flex flex-col gap-6 rounded-lg ${border} ${soft} p-6 break-inside-avoid sm:flex-row sm:items-center sm:justify-between sm:p-8`}
    >
      <div className="flex items-start gap-4">
        <Icon aria-hidden="true" className={`mt-1 size-8 shrink-0 ${text}`} />
        <div>
          <p className={`text-3xl font-semibold tracking-tight sm:text-4xl ${text}`}>
            {DECISION_LABELS[decision]}
          </p>
          {recommendation && <p className="mt-2 max-w-prose text-base text-fg">{recommendation}</p>}
        </div>
      </div>
      <div className="flex items-center gap-3 sm:flex-col sm:gap-1">
        <ScoreRing score={score} decision={decision} size="lg" />
        <span className="text-sm text-fg-muted">Release score out of 100</span>
      </div>
    </section>
  )
}
