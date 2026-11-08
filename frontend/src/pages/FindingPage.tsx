import {
  BadgeCheck,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  SearchCheck,
  Wrench,
} from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { useApi } from '../auth/context'
import { Breadcrumbs } from '../components/Breadcrumbs'
import { ReviewLabel, SeverityLabel } from '../components/labels'
import { AsideCard, SplitLayout } from '../components/SplitLayout'
import { CopyButton } from '../components/ui/CopyButton'
import { SectionTabs } from '../components/ui/SectionTabs'
import { EmptyState, ErrorState, PageHeader } from '../components/states'
import { LoadingState } from '../components/ui/Spinner'
import { EvidenceViewer } from '../features/evidence/EvidenceViewer'
import { CATEGORY_LABELS, checkLabel, formatConfidence, hostOf, sortFindings } from '../lib/format'
import { useAsync } from '../lib/useAsync'

export function FindingPage() {
  const { scanId = '', findingId = '' } = useParams()
  const api = useApi()
  const report = useAsync(() => api.getReport(scanId), `report:${scanId}`)
  const [tab, setTab] = useState('overview')

  const scanHost = report.data ? hostOf(report.data.scan.target_url) : 'Scan'
  const back = (
    <Breadcrumbs
      items={[
        { label: 'Scans', to: '/' },
        { label: scanHost, to: `/scans/${scanId}` },
        { label: 'Finding' },
      ]}
    />
  )

  if (report.data === undefined) {
    return (
      <div className="flex flex-col gap-6">
        {back}
        {report.loading ? (
          <LoadingState label="Loading finding…" />
        ) : (
          <ErrorState error={report.error} onRetry={report.reload} />
        )}
      </div>
    )
  }

  const inReview = report.data.needs_review.find((f) => f.id === findingId)
  const finding = report.data.findings.find((f) => f.id === findingId) ?? inReview
  if (!finding) {
    return (
      <div className="flex flex-col gap-6">
        {back}
        <EmptyState icon={SearchCheck} title="Finding not found">
          It may have been merged with a duplicate during verification.
        </EmptyState>
      </div>
    )
  }

  const all = [...sortFindings(report.data.findings), ...sortFindings(report.data.needs_review)]
  const at = all.findIndex((f) => f.id === finding.id)
  const prev = at > 0 ? all[at - 1] : undefined
  const next = at >= 0 && at < all.length - 1 ? all[at + 1] : undefined
  const hrefOf = (id: string) => `/scans/${scanId}/findings/${encodeURIComponent(id)}`
  const stepLink =
    'neu inline-flex min-h-11 flex-1 items-center gap-2 rounded-md border border-glass-edge bg-raised px-3 text-sm font-medium text-fg hover:text-accent'

  const aside = (
    <>
      <AsideCard title="At a glance">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-4">
          <div>
            <dt className="text-xs text-fg-muted">Severity</dt>
            <dd className="mt-1">
              <SeverityLabel severity={finding.severity} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-fg-muted">Confidence</dt>
            <dd className="mt-1 text-sm text-fg tabular-nums">
              {formatConfidence(finding.confidence)}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-fg-muted">Verification</dt>
            <dd className="mt-1 text-sm">
              {finding.verified ? (
                <span className="inline-flex items-center gap-1.5 text-success">
                  <BadgeCheck aria-hidden="true" className="size-4" />
                  Re-checked
                </span>
              ) : (
                <span className="text-fg-muted">Not re-checked</span>
              )}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-fg-muted">Check</dt>
            <dd className="mt-1 font-mono text-xs break-all text-fg">{finding.check_id}</dd>
          </div>
        </dl>
      </AsideCard>
      <AsideCard title={`In this scan (${at + 1} of ${all.length})`}>
        <nav aria-label="Findings in this scan" className="flex flex-col gap-3">
          <ul className="flex max-h-72 flex-col gap-1 overflow-y-auto">
            {all.map((item) => {
              const current = item.id === finding.id
              return (
                <li key={item.id}>
                  <Link
                    to={hrefOf(item.id)}
                    aria-current={current ? 'page' : undefined}
                    className={`flex min-h-11 items-center gap-2 rounded-md px-2 text-sm transition-[color,box-shadow,background-color] ${
                      current
                        ? 'bg-raised text-accent shadow-neu-inset'
                        : 'neu-soft text-fg-muted hover:bg-raised hover:text-fg'
                    }`}
                  >
                    <SeverityLabel severity={item.severity} />
                    <span className="truncate">{item.title}</span>
                  </Link>
                </li>
              )
            })}
          </ul>
          <div className="flex gap-2">
            {prev ? (
              <Link to={hrefOf(prev.id)} className={stepLink}>
                <ChevronLeft aria-hidden="true" className="size-4" />
                Previous
              </Link>
            ) : (
              <span className="flex-1" />
            )}
            {next && (
              <Link to={hrefOf(next.id)} className={`${stepLink} justify-end`}>
                Next
                <ChevronRight aria-hidden="true" className="size-4" />
              </Link>
            )}
          </div>
        </nav>
      </AsideCard>
    </>
  )

  return (
    <article aria-labelledby="page-title" className="flex flex-col gap-8">
      <div className="flex flex-col gap-2">
        {back}
        <PageHeader
          eyebrow={
            <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
              <SeverityLabel severity={finding.severity} />
              {inReview && <ReviewLabel />}
              <span>{CATEGORY_LABELS[finding.category]}</span>
              <span>{checkLabel(finding.check_id)}</span>
            </span>
          }
          title={<span id="page-title">{finding.title}</span>}
          description={
            <a
              href={finding.url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1.5 font-mono text-xs break-all hover:text-fg"
            >
              {finding.url}
              <ExternalLink aria-hidden="true" className="size-3.5 shrink-0" />
              <span className="sr-only">(opens the target site in a new tab)</span>
            </a>
          }
        />
      </div>

      <SplitLayout aside={aside} asideLabel="Finding summary">
        {inReview && (
          <p className="rounded-lg glass border border-dashed border-line-strong px-4 py-3 text-sm text-fg">
            <span className="font-medium">Needs manual review.</span> Confidence is below 50%, so
            this finding is not counted in the score.
          </p>
        )}

        <SectionTabs
          label="Finding sections"
          active={tab}
          onChange={setTab}
          tabs={[
            {
              id: 'overview',
              label: 'Overview',
              content: (
                <div className="grid gap-4 lg:grid-cols-2">
                  <section
                    aria-labelledby="impact-title"
                    className="glass rounded-lg border border-glass-edge p-5"
                  >
                    <h2 id="impact-title" className="label-mono text-fg-muted">
                      Impact
                    </h2>
                    <p className="mt-3 text-base leading-relaxed text-fg">{finding.impact}</p>
                  </section>
                  <section
                    aria-labelledby="fix-title"
                    className="glass rounded-lg border border-glass-edge p-5"
                  >
                    <h2 id="fix-title" className="label-mono flex items-center gap-2 text-fg-muted">
                      <Wrench aria-hidden="true" className="size-4 text-success" />
                      Suggested fix
                    </h2>
                    <p className="mt-3 text-base leading-relaxed text-fg">
                      {finding.recommended_fix}
                    </p>
                  </section>
                </div>
              ),
            },
            {
              id: 'reproduce',
              label: 'Reproduce',
              count: finding.reproduction.length,
              content: (
                <section aria-label="Steps to reproduce">
                  <ol className="glass flex flex-col divide-y divide-line rounded-lg border border-glass-edge">
                    {finding.reproduction.map((step, index) => (
                      <li
                        key={index}
                        className="flex items-center gap-4 py-1 pr-1 pl-4 text-sm text-fg"
                      >
                        <span
                          aria-hidden="true"
                          className="w-6 shrink-0 text-center font-mono text-xs text-fg-muted tabular-nums"
                        >
                          {String(index + 1).padStart(2, '0')}
                        </span>
                        <span className="min-w-0 flex-1 py-2 leading-relaxed">{step}</span>
                        <CopyButton text={step} label={`Copy step ${index + 1}`} />
                      </li>
                    ))}
                  </ol>
                </section>
              ),
            },
            {
              id: 'evidence',
              label: 'Evidence',
              count: finding.evidence.length,
              content: <EvidenceViewer scanId={scanId} evidence={finding.evidence} />,
            },
          ]}
        />
      </SplitLayout>
    </article>
  )
}
