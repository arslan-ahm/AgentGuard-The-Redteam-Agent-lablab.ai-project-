import { FileText, GitPullRequestArrow, Hourglass, Send, UserCheck } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import type { ApprovalAction } from '../api/contracts'
import type { ApprovalResult } from '../api/schemas'
import { useApi } from '../auth/context'
import { Breadcrumbs } from '../components/Breadcrumbs'
import { DecisionLabel, StatusLabel } from '../components/labels'
import { ScoreRing } from '../components/ScoreRing'
import { AsideCard, SplitLayout } from '../components/SplitLayout'
import { ErrorState, PageHeader } from '../components/states'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { buttonClasses } from '../components/ui/buttonStyles'
import { SectionTabs } from '../components/ui/SectionTabs'
import { LoadingState } from '../components/ui/Spinner'
import { ActivityFeed } from '../features/scan/ActivityFeed'
import { ApprovalDialog } from '../features/scan/ApprovalDialog'
import { ContainmentAlert } from '../features/scan/ContainmentAlert'
import { FindingsList } from '../features/scan/FindingsList'
import { ConnectionStatus, ScanProgress } from '../features/scan/ScanProgress'
import { decisionOf, FINAL_STATUSES, formatDateTime, hostOf, PROFILE_LABELS } from '../lib/format'
import { useAsync } from '../lib/useAsync'
import { useScanEvents } from '../lib/useScanEvents'

/** Remounts per scan id so no state carries over between scans. */
export function ScanPage() {
  const { scanId = '' } = useParams()
  return <ScanView key={scanId} scanId={scanId} />
}

function ScanView({ scanId }: { scanId: string }) {
  const api = useApi()
  const live = useScanEvents(api, scanId)
  const [approval, setApproval] = useState<ApprovalAction | null>(null)
  const [tab, setTab] = useState<string | null>(null)
  const [decisions, setDecisions] = useState<Partial<Record<ApprovalAction, ApprovalResult>>>({})
  const [statusAfterDecision, setStatusAfterDecision] = useState<ApprovalResult['scan_status']>()
  // The event stream closes at awaiting_approval, so an approval's new status comes from its response.
  const scan =
    live.scan && statusAfterDecision ? { ...live.scan, status: statusAfterDecision } : live.scan

  const hasResults = scan
    ? scan.status === 'awaiting_approval' || scan.status === 'completed' || scan.status === 'failed'
    : false
  const report = useAsync(
    () => (hasResults ? api.getReport(scanId) : Promise.resolve(undefined)),
    `${scanId}:${hasResults}`,
  )

  if (!scan) {
    if (live.connection === 'error') return <ErrorState error={live.error} />
    return <LoadingState label="Loading scan…" />
  }

  const decision = decisionOf(scan.score, scan.recommendation)
  const findings = report.data?.findings ?? []
  const needsReview = report.data?.needs_review ?? []
  const canApprove = scan.status === 'awaiting_approval' || scan.status === 'completed'
  const finished = FINAL_STATUSES.has(scan.status)

  function onDecided(result: ApprovalResult) {
    setDecisions((d) => ({ ...d, [result.action]: result }))
    setStatusAfterDecision(result.scan_status)
  }

  function approvalButton(action: ApprovalAction, label: string, icon: ReactNode) {
    const decided = decisions[action]
    return (
      <Button
        variant="secondary"
        icon={icon}
        disabled={decided !== undefined}
        onClick={() => setApproval(action)}
      >
        {decided ? `${label}: ${decided.approved ? 'approved' : 'rejected'}` : label}
      </Button>
    )
  }

  const findingsBody =
    scan.status === 'blocked' ? (
      <p className="text-sm text-fg-muted">No tests ran.</p>
    ) : !hasResults ? (
      <div className="glass flex items-start gap-3 rounded-lg border border-dashed border-line-strong p-5 text-sm text-fg-muted">
        <Hourglass aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        Findings appear here once the tests finish and the verifier has re-checked them.
      </div>
    ) : report.data === undefined && report.loading ? (
      <LoadingState label="Loading findings…" />
    ) : report.data === undefined ? (
      <ErrorState error={report.error} onRetry={report.reload} />
    ) : findings.length === 0 && needsReview.length === 0 ? (
      <p className="glass rounded-lg border border-glass-edge px-4 py-6 text-sm text-fg-muted">
        No issues found by the checks in this profile.
      </p>
    ) : (
      <FindingsList findings={findings} needsReview={needsReview} scanId={scan.id} />
    )

  const reportLink = finished && scan.status !== 'blocked' && (
    <Link to={`/scans/${scan.id}/report`} className={buttonClasses('primary', 'w-full')}>
      <FileText aria-hidden="true" className="size-4" />
      View report
    </Link>
  )

  const aside = (
    <>
      <AsideCard title="Release score">
        {decision && scan.score !== null && scan.score !== undefined ? (
          <div className="flex items-center gap-4">
            <ScoreRing score={scan.score} decision={decision} size="lg" />
            <div className="flex flex-col gap-2">
              <DecisionLabel decision={decision} />
              <span className="text-sm text-fg-muted">out of 100</span>
            </div>
          </div>
        ) : (
          <p className="text-sm text-fg-muted">
            {scan.status === 'blocked'
              ? 'No score: the scan was blocked before it started.'
              : 'Appears when the tests finish and the verifier has re-checked the findings.'}
          </p>
        )}
        {reportLink && <div className="mt-4">{reportLink}</div>}
      </AsideCard>

      <AsideCard title="Details">
        <dl className="flex flex-col gap-3 text-sm">
          <div className="flex items-center justify-between gap-3">
            <dt className="text-fg-muted">Status</dt>
            <dd>
              <StatusLabel status={scan.status} />
            </dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-fg-muted">Profile</dt>
            <dd className="text-fg">{PROFILE_LABELS[scan.profile]}</dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-fg-muted">Started</dt>
            <dd className="text-fg tabular-nums">{formatDateTime(scan.created_at)}</dd>
          </div>
        </dl>
      </AsideCard>

      {canApprove && (
        <section
          aria-labelledby="approval-title"
          className="glass flex flex-col gap-4 rounded-lg border border-glass-edge p-5"
        >
          <div className="flex items-start gap-3">
            <UserCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-accent" />
            <div>
              <h2 id="approval-title" className="font-semibold text-fg">
                Human approval
              </h2>
              <p className="mt-1 text-sm text-fg-muted">Records your decision. Nothing is sent.</p>
            </div>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
            {approvalButton(
              'github_issue',
              'GitHub issue',
              <GitPullRequestArrow aria-hidden="true" className="size-4" />,
            )}
            {approvalButton(
              'send_report',
              'Send report',
              <Send aria-hidden="true" className="size-4" />,
            )}
          </div>
        </section>
      )}
    </>
  )

  return (
    <section aria-labelledby="page-title" className="flex flex-col gap-8">
      <div className="flex flex-col gap-2">
        <Breadcrumbs items={[{ label: 'Scans', to: '/' }, { label: hostOf(scan.target_url) }]} />
        <PageHeader
          title={<span id="page-title">{hostOf(scan.target_url)}</span>}
          description={<span className="font-mono text-xs break-all">{scan.target_url}</span>}
        />
      </div>

      <SplitLayout aside={aside} asideLabel="Scan summary" asideFirst>
        {scan.status === 'blocked' && (
          <Alert tone="error" title="Scan blocked before it started">
            {scan.error ?? 'The target was refused by the URL policy.'} Nothing was sent to the
            target.
          </Alert>
        )}
        {scan.status === 'failed' && (
          <Alert tone="error" title="Scan failed">
            {scan.error ?? 'The scan stopped with an error.'}
          </Alert>
        )}

        <ContainmentAlert events={live.events} />

        {scan.status !== 'blocked' && (
          <div className="glass rounded-lg border border-glass-edge p-5">
            <ScanProgress scan={scan} />
          </div>
        )}

        <SectionTabs
          label="Scan sections"
          active={tab ?? (hasResults ? 'findings' : 'activity')}
          onChange={setTab}
          tabs={[
            {
              id: 'findings',
              label: 'Findings',
              count: report.data ? findings.length + needsReview.length : undefined,
              content: findingsBody,
            },
            {
              id: 'activity',
              label: 'Activity',
              count: live.events.length,
              content: (
                <>
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm text-fg-muted">
                      Every allowed and blocked action, from the append-only, hash-chained audit
                      log.
                    </p>
                    <ConnectionStatus connection={live.connection} />
                  </div>
                  <div className="glass overflow-hidden rounded-lg border border-glass-edge">
                    <ActivityFeed events={live.events} live={live.connection === 'live'} />
                  </div>
                </>
              ),
            },
          ]}
        />
      </SplitLayout>

      <ApprovalDialog
        action={approval}
        scan={scan}
        findings={findings}
        onClose={() => setApproval(null)}
        onDecided={onDecided}
      />
    </section>
  )
}
