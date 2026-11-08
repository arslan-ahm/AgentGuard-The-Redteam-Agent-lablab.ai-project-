import {
  ChevronRight,
  FileDown,
  FileJson,
  Hourglass,
  Paperclip,
  Printer,
  Wrench,
} from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import type { Finding } from '../api/contracts'
import { SEVERITIES } from '../api/contracts'
import { useApi } from '../auth/context'
import { Breadcrumbs } from '../components/Breadcrumbs'
import { AsideCard, SplitLayout } from '../components/SplitLayout'
import { ReviewLabel, SeverityLabel } from '../components/labels'
import { EmptyState, ErrorState, PageHeader } from '../components/states'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { LoadingState } from '../components/ui/Spinner'
import { DecisionBanner } from '../features/report/DecisionBanner'
import { downloadText, reportBaseName } from '../features/report/download'
import { errorText } from '../lib/errors'
import {
  CATEGORY_LABELS,
  checkLabel,
  countBySeverity,
  DECISION_LABELS,
  decisionOf,
  FINAL_STATUSES,
  formatConfidence,
  formatDateTime,
  hostOf,
  PROFILE_LABELS,
  SEVERITY_LABELS,
  sortFindings,
} from '../lib/format'
import { useActiveSection } from '../lib/useActiveSection'
import { useAsync } from '../lib/useAsync'

const SEVERITY_BAR: Record<Finding['severity'], string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
}

function FindingSection({
  finding,
  index,
  scanId,
}: {
  finding: Finding
  index: number
  scanId: string
}) {
  return (
    <li
      id={`fix-${index + 1}`}
      className="glass lift flex scroll-mt-24 flex-col rounded-lg border border-glass-edge break-inside-avoid"
    >
      <div className="flex items-start gap-4 p-5">
        <span className="w-6 shrink-0 pt-0.5 font-mono text-sm text-fg-muted tabular-nums">
          {String(index + 1).padStart(2, '0')}
        </span>
        <div className="flex min-w-0 flex-1 flex-col gap-2">
          <SeverityLabel severity={finding.severity} />
          <h3 className="text-base font-semibold text-fg">
            <Link
              to={`/scans/${scanId}/findings/${encodeURIComponent(finding.id)}`}
              className="hover:text-accent print:no-underline"
            >
              {finding.title}
            </Link>
          </h3>
          <p className="font-mono text-xs break-all text-fg-muted">{finding.url}</p>
        </div>
        <dl className="hidden shrink-0 text-right sm:block">
          <dt className="label-mono text-fg-muted">Confidence</dt>
          <dd className="mt-1 text-sm text-fg tabular-nums">
            {formatConfidence(finding.confidence)}
          </dd>
        </dl>
      </div>
      <div className="grid gap-6 border-t border-line p-5 md:grid-cols-3">
        <div>
          <h4 className="label-mono text-fg-muted">Impact</h4>
          <p className="mt-2 text-sm leading-relaxed text-fg">{finding.impact}</p>
          <p className="mt-3 text-xs text-fg-muted">
            {CATEGORY_LABELS[finding.category]} · {checkLabel(finding.check_id)}
            <span className="sm:hidden"> · confidence {formatConfidence(finding.confidence)}</span>
          </p>
        </div>
        <div>
          <h4 className="label-mono text-fg-muted">Reproduce</h4>
          <ol className="mt-2 flex flex-col gap-1.5 text-sm text-fg">
            {finding.reproduction.map((step, i) => (
              <li key={i} className="flex gap-2">
                <span className="w-4 shrink-0 font-mono text-xs leading-5 text-fg-muted">
                  {i + 1}
                </span>
                <span className="min-w-0 leading-5">{step}</span>
              </li>
            ))}
          </ol>
        </div>
        <div>
          <h4 className="label-mono flex items-center gap-1.5 text-fg-muted">
            <Wrench aria-hidden="true" className="size-3.5 text-success" />
            Fix
          </h4>
          <p className="mt-2 text-sm leading-relaxed text-fg">{finding.recommended_fix}</p>
        </div>
      </div>
      {finding.evidence.length > 0 && (
        <div className="border-t border-line px-5 py-3 print:hidden">
          <Link
            to={`/scans/${scanId}/findings/${encodeURIComponent(finding.id)}`}
            className="inline-flex min-h-11 items-center gap-1.5 text-sm font-medium text-accent hover:text-accent-hover"
          >
            <Paperclip aria-hidden="true" className="size-4" />
            View evidence ({finding.evidence.length})
            <ChevronRight aria-hidden="true" className="size-4" />
          </Link>
        </div>
      )}
    </li>
  )
}

export function ReportPage() {
  const { scanId = '' } = useParams()
  const api = useApi()
  const report = useAsync(() => api.getReport(scanId), `report:${scanId}`)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const fixCount = report.data?.findings.length ?? 0
  const sectionIds = [
    'decision',
    'summary',
    'fixes',
    ...Array.from({ length: fixCount }, (_, i) => `fix-${i + 1}`),
    ...(report.data?.needs_review.length ? ['review'] : []),
  ]
  const activeSection = useActiveSection(report.data ? sectionIds : [])

  const back = (
    <Breadcrumbs
      items={[
        { label: 'Scans', to: '/' },
        {
          label: report.data ? hostOf(report.data.scan.target_url) : 'Scan',
          to: `/scans/${scanId}`,
        },
        { label: 'Report' },
      ]}
    />
  )

  if (report.data === undefined) {
    return (
      <div className="flex flex-col gap-6">
        {back}
        {report.loading ? (
          <LoadingState label="Loading report…" />
        ) : (
          <ErrorState error={report.error} onRetry={report.reload} />
        )}
      </div>
    )
  }

  const { scan, findings, needs_review: needsReview } = report.data
  if (!FINAL_STATUSES.has(scan.status) || scan.status === 'blocked') {
    return (
      <div className="flex flex-col gap-6">
        {back}
        <EmptyState icon={Hourglass} title="The report isn’t ready">
          {scan.status === 'blocked'
            ? 'This scan was blocked by the safety policy before any tests ran.'
            : 'It is available once the scan finishes and findings are verified.'}
        </EmptyState>
      </div>
    )
  }

  const decision = decisionOf(scan.score, scan.recommendation)
  const sorted = sortFindings(findings)
  const counts = countBySeverity(findings)
  const base = reportBaseName(scan.target_url, scan.created_at)

  async function exportMarkdown() {
    setExporting(true)
    setExportError(null)
    try {
      downloadText(`${base}.md`, await api.getReportMarkdown(scanId), 'text/markdown')
    } catch (error) {
      setExportError(errorText(error))
    } finally {
      setExporting(false)
    }
  }

  const tocLink = (id: string, label: ReactNode, nested = false) => (
    <a
      href={`#${id}`}
      aria-current={activeSection === id ? 'location' : undefined}
      className={`flex min-h-10 items-center gap-2 rounded-md px-2 text-sm transition-[color,box-shadow,background-color] ${
        nested ? 'pl-5' : ''
      } ${
        activeSection === id
          ? 'bg-raised text-accent shadow-neu-inset'
          : 'neu-soft text-fg-muted hover:bg-raised hover:text-fg'
      }`}
    >
      {label}
    </a>
  )

  const aside = (
    <>
      <AsideCard title="On this page" className="print:hidden">
        <nav aria-label="On this page">
          <ul className="flex flex-col gap-1">
            <li>{tocLink('decision', 'Release decision')}</li>
            <li>{tocLink('summary', 'Executive summary')}</li>
            <li>
              {tocLink('fixes', 'Prioritized fixes')}
              {sorted.length > 0 && (
                <ul className="mt-1 flex max-h-64 flex-col gap-1 overflow-y-auto">
                  {sorted.map((finding, index) => (
                    <li key={finding.id}>
                      {tocLink(
                        `fix-${index + 1}`,
                        <span className="truncate">
                          <span className="tabular-nums">{index + 1}.</span> {finding.title}
                        </span>,
                        true,
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </li>
            {needsReview.length > 0 && <li>{tocLink('review', 'Needs manual review')}</li>}
          </ul>
        </nav>
      </AsideCard>
      <AsideCard title="Export" className="print:hidden">
        <div className="flex flex-col gap-2">
          <Button
            variant="secondary"
            className="w-full justify-start"
            loading={exporting}
            onClick={exportMarkdown}
            icon={<FileDown aria-hidden="true" className="size-4" />}
          >
            Markdown
          </Button>
          <Button
            variant="secondary"
            className="w-full justify-start"
            onClick={() =>
              downloadText(`${base}.json`, JSON.stringify(report.data, null, 2), 'application/json')
            }
            icon={<FileJson aria-hidden="true" className="size-4" />}
          >
            JSON
          </Button>
          <Button
            variant="secondary"
            className="w-full justify-start"
            onClick={() => window.print()}
            icon={<Printer aria-hidden="true" className="size-4" />}
          >
            Save as PDF
          </Button>
        </div>
      </AsideCard>
    </>
  )

  return (
    <article aria-labelledby="page-title" className="flex flex-col gap-8">
      <div className="flex flex-col gap-2">
        {back}
        <PageHeader
          eyebrow="Release readiness report"
          title={<span id="page-title">{hostOf(scan.target_url)}</span>}
          description={
            <span className="flex flex-wrap gap-x-4 gap-y-1">
              <span className="font-mono text-xs break-all">{scan.target_url}</span>
              <span>{PROFILE_LABELS[scan.profile]}</span>
              <span className="tabular-nums">{formatDateTime(scan.created_at)}</span>
            </span>
          }
        />
      </div>

      <SplitLayout aside={aside} asideLabel="Report tools">
        {exportError && (
          <Alert tone="error" title="Export failed">
            {exportError}
          </Alert>
        )}

        <div id="decision" className="scroll-mt-24">
          {decision && scan.score !== null && scan.score !== undefined && (
            <DecisionBanner
              decision={decision}
              score={scan.score}
              recommendation={scan.recommendation}
            />
          )}
        </div>

        <section
          id="summary"
          aria-labelledby="summary-title"
          className="flex scroll-mt-24 flex-col gap-4"
        >
          <h2 id="summary-title" className="text-lg font-semibold text-fg">
            Executive summary
          </h2>
          <p className="max-w-prose text-sm leading-relaxed text-fg">
            {scan.summary ??
              `${findings.length} verified ${findings.length === 1 ? 'finding' : 'findings'} across QA, security and accessibility checks.`}
          </p>
          {findings.length > 0 && (
            <div aria-hidden="true" className="flex h-2 gap-0.5 overflow-hidden rounded-full">
              {SEVERITIES.filter((severity) => counts[severity] > 0).map((severity) => (
                <span
                  key={severity}
                  className={SEVERITY_BAR[severity]}
                  style={{ flexGrow: counts[severity] }}
                />
              ))}
            </div>
          )}
          <dl className="grid grid-cols-2 divide-line overflow-hidden glass rounded-lg border border-glass-edge sm:grid-cols-4 sm:divide-x">
            {SEVERITIES.map((severity) => (
              <div key={severity} className="flex flex-col gap-1 px-4 py-3">
                <dt>
                  <SeverityLabel severity={severity} />
                </dt>
                <dd className="text-2xl font-semibold text-fg tabular-nums">
                  {counts[severity]}
                  <span className="sr-only">
                    {' '}
                    {SEVERITY_LABELS[severity].toLowerCase()} findings
                  </span>
                </dd>
              </div>
            ))}
          </dl>
        </section>

        <section
          id="fixes"
          aria-labelledby="fixes-title"
          className="flex scroll-mt-24 flex-col gap-4"
        >
          <h2 id="fixes-title" className="text-lg font-semibold text-fg">
            Prioritized fixes
          </h2>
          {sorted.length === 0 ? (
            <p className="text-sm text-fg-muted">No verified findings.</p>
          ) : (
            <ol className="flex flex-col gap-4">
              {sorted.map((finding, index) => (
                <FindingSection key={finding.id} finding={finding} index={index} scanId={scanId} />
              ))}
            </ol>
          )}
        </section>

        {needsReview.length > 0 && (
          <section
            id="review"
            aria-labelledby="review-title"
            className="flex scroll-mt-24 flex-col gap-3"
          >
            <h2 id="review-title" className="text-lg font-semibold text-fg">
              Needs manual review
            </h2>
            <p className="text-sm text-fg-muted">Confidence below 50%. Not counted in the score.</p>
            <ul className="divide-y divide-line rounded-lg glass border border-dashed border-line-strong">
              {sortFindings(needsReview).map((finding) => (
                <li
                  key={finding.id}
                  className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-3"
                >
                  <ReviewLabel />
                  <span className="text-sm text-fg">{finding.title}</span>
                  <span className="text-xs text-fg-muted">
                    {SEVERITY_LABELS[finding.severity]} if confirmed
                  </span>
                  <span className="text-xs text-fg-muted tabular-nums">
                    confidence {formatConfidence(finding.confidence)}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}

        <footer className="flex flex-col gap-2 border-t border-line pt-6 text-sm">
          {decision && (
            <p className="text-fg">
              <span className="text-fg-muted">Decision: </span>
              <span className="font-semibold">{DECISION_LABELS[decision]}</span>
              {scan.score !== null && scan.score !== undefined && (
                <span className="text-fg-muted tabular-nums"> · score {scan.score}/100</span>
              )}
            </p>
          )}
          <p className="font-mono text-xs break-all text-fg-muted">
            Scan {scan.id}, {scan.target_url}, {formatDateTime(scan.created_at)}
          </p>
          <p className="text-xs text-fg-muted">
            Generated by AgentGuard. Safe, non-destructive checks only, run in disposable sandboxes
            on a target the requester attested they are authorized to test.
          </p>
        </footer>
      </SplitLayout>
    </article>
  )
}
