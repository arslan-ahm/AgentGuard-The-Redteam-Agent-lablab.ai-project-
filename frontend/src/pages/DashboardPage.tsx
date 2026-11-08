import {
  ChevronRight,
  Layers,
  Search,
  X,
  Plus,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  type LucideIcon,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import type { ScanDetail } from '../api/schemas'
import { useApi } from '../auth/context'
import { DecisionLabel, StatusLabel } from '../components/labels'
import { ScoreRing } from '../components/ScoreRing'
import { AsideCard } from '../components/SplitLayout'
import { EmptyState, ErrorState, PageHeader } from '../components/states'
import { LoadingState } from '../components/ui/Spinner'
import {
  DECISION_LABELS,
  decisionOf,
  FINAL_STATUSES,
  formatDateTime,
  hostOf,
  pathOf,
  PROFILE_LABELS,
} from '../lib/format'
import { useAsync } from '../lib/useAsync'

const REFRESH_MS = 5_000

type Filter = 'all' | 'active' | 'awaiting' | 'done' | 'stopped'

const FILTERS: { value: Filter; label: string; match: (s: ScanDetail) => boolean }[] = [
  { value: 'all', label: 'All', match: () => true },
  { value: 'active', label: 'Running', match: (s) => !FINAL_STATUSES.has(s.status) },
  { value: 'awaiting', label: 'Awaiting', match: (s) => s.status === 'awaiting_approval' },
  { value: 'done', label: 'Completed', match: (s) => s.status === 'completed' },
  {
    value: 'stopped',
    label: 'Blocked or failed',
    match: (s) => s.status === 'blocked' || s.status === 'failed',
  },
]

/** How the finished scans split across the three release decisions. */
function DecisionMix({ scans }: { scans: ScanDetail[] }) {
  const tally = { block: 0, fixFirst: 0, safe: 0 }
  for (const scan of scans) {
    const decision = decisionOf(scan.score, scan.recommendation)
    if (decision) tally[decision] += 1
  }
  const scored = tally.block + tally.fixFirst + tally.safe
  const rows = [
    { key: 'block' as const, bar: 'bg-bad' },
    { key: 'fixFirst' as const, bar: 'bg-warn' },
    { key: 'safe' as const, bar: 'bg-success' },
  ]
  if (scored === 0) return <p className="text-sm text-fg-muted">No scored scans yet.</p>
  return (
    <ul className="flex flex-col gap-3">
      {rows.map((row) => (
        <li key={row.key} className="flex flex-col gap-1.5">
          <span className="flex items-center justify-between text-sm">
            <span className="text-fg">{DECISION_LABELS[row.key]}</span>
            <span className="text-fg-muted tabular-nums">{tally[row.key]}</span>
          </span>
          <span aria-hidden="true" className="h-1.5 overflow-hidden rounded-full bg-raised">
            <span
              className={`block h-full rounded-full transition-[width] duration-500 ${row.bar}`}
              style={{ width: `${(tally[row.key] / scored) * 100}%` }}
            />
          </span>
        </li>
      ))}
    </ul>
  )
}

function Score({ scan }: { scan: ScanDetail }) {
  const decision = decisionOf(scan.score, scan.recommendation)
  if (scan.score === null || scan.score === undefined || !decision) {
    return (
      <span className="text-sm text-fg-muted">
        n/a<span className="sr-only"> (no score)</span>
      </span>
    )
  }
  return (
    <span className="flex items-center gap-3">
      <ScoreRing score={scan.score} decision={decision} />
      <DecisionLabel decision={decision} />
    </span>
  )
}

function Target({ scan }: { scan: ScanDetail }) {
  const path = pathOf(scan.target_url)
  const blocked = scan.status === 'blocked'
  return (
    <span className="flex min-w-0 items-start gap-2">
      {blocked && <ShieldOff aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-bad" />}
      <span className="flex min-w-0 flex-col">
        <span className="truncate font-mono text-sm font-medium text-fg">
          {hostOf(scan.target_url)}
        </span>
        {path !== '/' && <span className="truncate font-mono text-xs text-fg-muted">{path}</span>}
        {blocked && (
          <span className="mt-1 text-xs text-bad">
            {scan.error ?? 'Refused by the safety policy'}
          </span>
        )}
      </span>
    </span>
  )
}

/** Three quiet counters taken from the scan list itself (no extra API calls). */
function Summary({ scans }: { scans: ScanDetail[] }) {
  const items: { label: string; value: number; icon: LucideIcon; tone: string; card: string }[] = [
    {
      label: 'Scans',
      value: scans.length,
      icon: Layers,
      tone: 'text-fg-muted',
      card: 'border-glass-edge',
    },
    {
      label: 'Awaiting',
      value: scans.filter((s) => s.status === 'awaiting_approval').length,
      icon: ShieldAlert,
      tone: 'text-warn',
      card: 'border-glass-edge',
    },
    {
      label: 'Blocked',
      value: scans.filter((s) => s.status === 'blocked').length,
      icon: ShieldOff,
      tone: 'text-bad',
      card: 'border-bad/30',
    },
  ]
  return (
    <dl className="grid grid-cols-3 gap-3">
      {items.map((item) => {
        const Icon = item.icon
        return (
          <div
            key={item.label}
            className={`glass lift flex flex-col justify-between gap-4 rounded-lg border px-4 py-4 ${item.card}`}
          >
            <dt className="flex items-center justify-between gap-2">
              <span className="label-mono text-fg-muted">{item.label}</span>
              <Icon aria-hidden="true" className={`size-4 ${item.tone}`} />
            </dt>
            <dd
              className={`text-4xl font-semibold tracking-tight tabular-nums ${item.value > 0 && item.label !== 'Scans' ? item.tone : 'text-fg'}`}
            >
              {item.value}
            </dd>
          </div>
        )
      })}
    </dl>
  )
}

export function DashboardPage() {
  const api = useApi()
  const navigate = useNavigate()
  const scans = useAsync(() => api.listScans(), 'scans')
  const [filter, setFilter] = useState<Filter>('all')
  const [query, setQuery] = useState('')
  const { reload } = scans
  const active = scans.data?.some((s) => !FINAL_STATUSES.has(s.status)) ?? false

  // Keep the list fresh while any scan is still running.
  useEffect(() => {
    if (!active) return
    const timer = setInterval(reload, REFRESH_MS)
    return () => clearInterval(timer)
  }, [active, reload])

  const newScan = (
    <Link
      to="/scans/new"
      className="inline-flex min-h-11 items-center gap-2 rounded-md bg-accent px-4 text-sm font-medium text-on-accent transition-colors hover:bg-accent-hover"
    >
      <Plus aria-hidden="true" className="size-4" />
      New scan
    </Link>
  )

  let body
  if (scans.data === undefined && scans.loading) {
    body = <LoadingState label="Loading scans…" />
  } else if (scans.data === undefined) {
    body = <ErrorState error={scans.error} onRetry={reload} />
  } else if (scans.data.length === 0) {
    body = (
      <EmptyState icon={ShieldCheck} title="No scans yet" action={newScan}>
        Start a scan on a site you own or are authorized to test. AgentGuard runs safe,
        non-destructive QA and security checks and returns a release decision with evidence.
      </EmptyState>
    )
  } else {
    const term = query.trim().toLowerCase()
    const rule = FILTERS.find((f) => f.value === filter) ?? FILTERS[0]
    const visible = scans.data.filter(
      (scan) => rule.match(scan) && (!term || scan.target_url.toLowerCase().includes(term)),
    )
    body = (
      <div className="flex flex-col gap-6">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <Summary scans={scans.data} />
          <AsideCard title="Release decisions">
            <DecisionMix scans={scans.data} />
          </AsideCard>
        </div>
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="label-mono text-fg-muted">Targets and audits</h2>
            {active && <span className="label-mono text-fg-muted">Auto-refresh 5s</span>}
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-2">
              {FILTERS.map((f) => {
                const count = scans.data!.filter(f.match).length
                const on = filter === f.value
                return (
                  <button
                    key={f.value}
                    type="button"
                    aria-pressed={on}
                    onClick={() => setFilter(f.value)}
                    className={`inline-flex min-h-11 items-center gap-2 rounded-md px-3 text-sm font-medium transition-[color,box-shadow,background-color] ${
                      on
                        ? 'bg-raised text-accent shadow-neu-inset'
                        : 'neu text-fg-muted hover:text-fg'
                    }`}
                  >
                    {f.label}
                    <span className="font-mono text-xs tabular-nums opacity-80">{count}</span>
                  </button>
                )
              })}
            </div>
            <label className="relative block sm:w-64">
              <span className="sr-only">Search targets</span>
              <Search
                aria-hidden="true"
                className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-muted"
              />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search targets"
                className="min-h-11 w-full rounded-md border border-line-strong bg-canvas/60 pr-3 pl-10 text-base text-fg shadow-neu-inset placeholder:text-fg-muted focus:border-accent sm:text-sm"
              />
            </label>
          </div>
        </div>

        {visible.length === 0 ? (
          <div className="glass flex flex-col items-start gap-3 rounded-lg border border-dashed border-line-strong p-6">
            <p className="text-sm text-fg">No scans match these filters.</p>
            <button
              type="button"
              onClick={() => {
                setFilter('all')
                setQuery('')
              }}
              className="neu inline-flex min-h-11 items-center gap-2 rounded-md border border-glass-edge bg-raised px-4 text-sm font-medium text-fg hover:text-accent"
            >
              <X aria-hidden="true" className="size-4" />
              Clear filters
            </button>
          </div>
        ) : (
          <>
            {/* Table from lg up; stacked cards on phones and tablets. */}
            <div className="glass hidden overflow-hidden rounded-lg border border-glass-edge lg:block">
              <table className="w-full table-fixed text-left">
                <caption className="sr-only">Scans, newest first</caption>
                <thead className="label-mono border-b border-line text-fg-muted">
                  <tr>
                    <th scope="col" className="w-[30%] px-4 py-3">
                      Target
                    </th>
                    <th scope="col" className="w-[14%] px-4 py-3">
                      Profile
                    </th>
                    <th scope="col" className="w-[19%] px-4 py-3">
                      Status
                    </th>
                    <th scope="col" className="w-[17%] px-4 py-3">
                      Score
                    </th>
                    <th scope="col" className="w-[16%] px-4 py-3">
                      Started
                    </th>
                    <th scope="col" className="w-16 px-2 py-3">
                      <span className="sr-only">Open</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {visible.map((scan) => (
                    <tr
                      key={scan.id}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                      className="group cursor-pointer transition-colors hover:bg-raised"
                    >
                      <td className="px-4 py-3">
                        <Target scan={scan} />
                      </td>
                      <td className="px-4 py-3 text-sm text-fg">{PROFILE_LABELS[scan.profile]}</td>
                      <td className="px-4 py-3">
                        <StatusLabel status={scan.status} />
                      </td>
                      <td className="px-4 py-3">
                        <Score scan={scan} />
                      </td>
                      <td className="px-4 py-3 text-sm whitespace-nowrap text-fg-muted tabular-nums">
                        {formatDateTime(scan.created_at)}
                      </td>
                      <td className="px-2 py-1.5 text-right">
                        <Link
                          to={`/scans/${scan.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex size-11 items-center justify-center rounded-md text-fg-muted transition-transform group-hover:translate-x-0.5 group-hover:text-fg hover:text-fg"
                          aria-label={`Open scan of ${hostOf(scan.target_url)}`}
                        >
                          <ChevronRight aria-hidden="true" className="size-4" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <ul className="flex flex-col gap-3 lg:hidden">
              {visible.map((scan) => (
                <li key={scan.id}>
                  <Link
                    to={`/scans/${scan.id}`}
                    className={`flex items-start gap-3 lift rounded-lg border px-4 py-4 ${
                      scan.status === 'blocked'
                        ? 'border-bad/40 bg-raised'
                        : 'glass border-glass-edge'
                    }`}
                  >
                    <span className="flex min-w-0 flex-1 flex-col gap-2">
                      <Target scan={scan} />
                      <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
                        <StatusLabel status={scan.status} />
                        <span className="text-sm text-fg-muted">
                          {PROFILE_LABELS[scan.profile]}
                        </span>
                      </span>
                      <Score scan={scan} />
                      <span className="text-xs text-fg-muted">
                        {formatDateTime(scan.created_at)}
                      </span>
                    </span>
                    <ChevronRight aria-hidden="true" className="mt-1 size-4 text-fg-muted" />
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    )
  }

  const awaiting = scans.data?.filter((s) => s.status === 'awaiting_approval').length ?? 0
  const description = scans.data
    ? `${scans.data.length} ${scans.data.length === 1 ? 'scan' : 'scans'}${
        awaiting ? ` · ${awaiting} awaiting your approval` : ''
      }`
    : 'Release-readiness audits of your web apps'

  return (
    <section aria-labelledby="page-title" className="flex flex-col gap-6">
      <PageHeader
        title={<span id="page-title">Scans</span>}
        description={description}
        actions={scans.data && scans.data.length > 0 ? newScan : undefined}
      />
      {body}
    </section>
  )
}
