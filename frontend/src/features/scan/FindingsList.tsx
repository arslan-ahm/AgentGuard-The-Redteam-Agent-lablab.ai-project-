import { BadgeCheck, ChevronRight } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { SEVERITIES, type Finding } from '../../api/contracts'
import { ReviewLabel, SeverityLabel } from '../../components/labels'
import {
  CATEGORY_LABELS,
  formatConfidence,
  hostOf,
  pathOf,
  SEVERITY_LABELS,
  sortFindings,
} from '../../lib/format'

type Filter = 'all' | Finding['category']

function FindingRow({
  finding,
  scanId,
  review = false,
}: {
  finding: Finding
  scanId: string
  review?: boolean
}) {
  return (
    <li>
      <Link
        to={`/scans/${scanId}/findings/${encodeURIComponent(finding.id)}`}
        className="group flex items-start gap-4 px-4 py-4 transition-colors hover:bg-raised"
      >
        <span className="hidden w-36 shrink-0 pt-0.5 sm:block">
          {review ? <ReviewLabel /> : <SeverityLabel severity={finding.severity} />}
        </span>
        <span className="flex min-w-0 flex-1 flex-col gap-1">
          <span className="sm:hidden">
            {review ? <ReviewLabel /> : <SeverityLabel severity={finding.severity} />}
          </span>
          <span className="font-medium text-fg">{finding.title}</span>
          <span className="line-clamp-1 text-sm text-fg-muted">{finding.impact}</span>
          <span className="truncate font-mono text-xs text-fg-muted">
            {review && `${SEVERITY_LABELS[finding.severity]} if confirmed. `}
            {CATEGORY_LABELS[finding.category]}: {hostOf(finding.url)}
            {pathOf(finding.url)}
          </span>
        </span>
        <span className="hidden shrink-0 flex-col items-end gap-1 text-sm sm:flex">
          <span className="text-fg tabular-nums">{formatConfidence(finding.confidence)}</span>
          {finding.verified ? (
            <span className="inline-flex items-center gap-1 text-xs text-success">
              <BadgeCheck aria-hidden="true" className="size-3.5" />
              Verified
            </span>
          ) : (
            <span className="text-xs text-fg-muted">Unverified</span>
          )}
        </span>
        <ChevronRight
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-fg-muted transition-transform group-hover:translate-x-0.5"
        />
      </Link>
    </li>
  )
}

/** Findings sorted by severity, with a category filter and the manual-review bucket. */
export function FindingsList({
  findings,
  needsReview,
  scanId,
}: {
  findings: Finding[]
  needsReview: Finding[]
  scanId: string
}) {
  const [filter, setFilter] = useState<Filter>('all')
  const sorted = sortFindings(findings)
  const visible = filter === 'all' ? sorted : sorted.filter((f) => f.category === filter)
  const counts = {
    all: findings.length,
    qa: findings.filter((f) => f.category === 'qa').length,
    security: findings.filter((f) => f.category === 'security').length,
    accessibility: findings.filter((f) => f.category === 'accessibility').length,
  }
  const filters: Filter[] = ['all', 'security', 'qa', 'accessibility']
  const bySeverity = SEVERITIES.map((severity) => ({
    severity,
    count: findings.filter((f) => f.severity === severity).length,
  })).filter((entry) => entry.count > 0)

  return (
    <div className="flex flex-col gap-4">
      {bySeverity.length > 0 && (
        <p className="text-sm text-fg-muted">
          {bySeverity
            .map(({ severity, count }) => `${count} ${SEVERITY_LABELS[severity].toLowerCase()}`)
            .join(', ')}
        </p>
      )}
      <div role="group" aria-label="Filter findings by category" className="flex flex-wrap gap-1">
        {filters.map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={filter === value}
            onClick={() => setFilter(value)}
            className={`inline-flex min-h-11 items-center gap-1.5 rounded-md px-3 text-sm transition-colors ${
              filter === value
                ? 'bg-raised font-medium text-fg'
                : 'text-fg-muted hover:bg-raised hover:text-fg'
            }`}
          >
            {value === 'all' ? 'All' : CATEGORY_LABELS[value]}
            <span className="text-fg-muted tabular-nums">{counts[value]}</span>
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <p className="glass rounded-lg border border-glass-edge px-4 py-6 text-sm text-fg-muted">
          No findings in this category.
        </p>
      ) : (
        <ul className="divide-y divide-line overflow-hidden glass rounded-lg border border-glass-edge">
          {visible.map((finding) => (
            <FindingRow key={finding.id} finding={finding} scanId={scanId} />
          ))}
        </ul>
      )}

      {needsReview.length > 0 && (
        <details className="group rounded-lg glass border border-dashed border-line-strong">
          <summary className="flex min-h-11 cursor-pointer items-center justify-between gap-3 px-4 text-sm font-medium text-fg">
            <span>
              Needs manual review{' '}
              <span className="font-normal text-fg-muted tabular-nums">({needsReview.length})</span>
            </span>
            <ChevronRight
              aria-hidden="true"
              className="size-4 text-fg-muted transition-transform group-open:rotate-90"
            />
          </summary>
          <p className="border-t border-dashed border-line-strong px-4 py-3 text-sm text-fg-muted">
            Not counted in the score. Confidence is below 50%, so someone needs to confirm them.
          </p>
          <ul className="divide-y divide-line border-t border-dashed border-line-strong">
            {sortFindings(needsReview).map((finding) => (
              <FindingRow key={finding.id} finding={finding} scanId={scanId} review />
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
