/**
 * In-memory `ApiClient` for mock mode (`bun run dev:mock`) and tests.
 *
 * Mirrors the real API's behaviour closely enough to build every screen without the backend:
 * the 5.8 error codes, a simulated scan run (planning, sandboxes, the containment block when
 * requested, verifying, awaiting approval) and an SSE-like stream with the same close rule as
 * `backend/app/api/routes.py` (one extra pass after a final state).
 */

import { ApiError, type ApiClient } from '../client'
import type { AuditEvent, Finding, ScanProfile, ScanStatus, Severity } from '../contracts'
import { RECOMMENDATIONS } from '../contracts'
import type { Report, ScanDetail } from '../schemas'
import { demoAudit, demoFindings, demoNeedsReview, fixtureScans, FIXTURE_IDS } from './fixtures'

/** Statuses after which the backend closes the event stream. */
const FINAL: ReadonlySet<ScanStatus> = new Set([
  'completed',
  'failed',
  'blocked',
  'awaiting_approval',
])

const TASKS_BY_PROFILE: Record<ScanProfile, string[]> = {
  smoke: ['qa.pages_load', 'qa.links_assets', 'qa.console_network_errors', 'security.headers'],
  qa: ['qa.pages_load', 'qa.forms', 'qa.login', 'qa.checkout', 'qa.search', 'qa.accessibility'],
  security: [
    'security.https_redirect',
    'security.headers',
    'security.cookies',
    'security.error_leak',
    'security.exposed_endpoints',
  ],
  full: [
    'qa.pages_load',
    'qa.forms',
    'qa.checkout',
    'security.error_leak',
    'security.headers',
    'security.cookies',
    'qa.accessibility',
  ],
}

const PENALTY: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 1 }

/** Brief 5.10, for mock data only (the real score comes from the backend). */
function mockScore(findings: Finding[]): { score: number; recommendation: string } {
  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + PENALTY[f.severity], 0))
  const recommendation =
    score < 50
      ? RECOMMENDATIONS.block
      : score < 80
        ? RECOMMENDATIONS.fixFirst
        : RECOMMENDATIONS.safe
  return { score, recommendation }
}

function findingsForProfile(scanId: string, profile: ScanProfile): Finding[] {
  const all = demoFindings(scanId)
  if (profile === 'full') return all
  if (profile === 'security') return all.filter((f) => f.category === 'security')
  if (profile === 'qa') return all.filter((f) => f.category !== 'security')
  return all.filter((f) => f.check_id === 'security.headers' || f.check_id === 'qa.accessibility')
}

/** Rough mirror of the URL policy, enough to demo a `403 target_blocked`. */
function blockedReason(target: string): string | null {
  let url: URL
  try {
    url = new URL(target)
  } catch {
    return 'not a valid URL'
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:')
    return 'only http and https are allowed'
  if (url.username || url.password) return 'credentials in the URL are not allowed'
  const host = url.hostname
  if (host === 'localhost' || host.endsWith('.localhost')) return 'loopback address is not allowed'
  if (/^127\./.test(host) || host === '[::1]') return 'loopback address is not allowed'
  if (/^169\.254\./.test(host)) return 'link-local / cloud metadata address is never allowed'
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) {
    return `target resolves to a private address (${host})`
  }
  return null
}

function placeholderImage(label: string): Blob {
  const safe = label.replace(/[<>&"']/g, '')
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="800" viewBox="0 0 1280 800"><rect width="1280" height="800" fill="#1b2330"/><text x="640" y="390" fill="#9fb0c3" font-family="sans-serif" font-size="28" text-anchor="middle">Mock evidence</text><text x="640" y="440" fill="#9fb0c3" font-family="monospace" font-size="22" text-anchor="middle">${safe}</text></svg>`
  return new Blob([svg], { type: 'image/svg+xml' })
}

export interface MockClientOptions {
  /** Delay between simulated scan steps. */
  stepMs?: number
  /** Start with the fixture scans (default true). */
  seed?: boolean
}

export function createMockClient(options: MockClientOptions = {}): ApiClient {
  const stepMs = options.stepMs ?? 700
  const scans = new Map<string, ScanDetail>()
  const findings = new Map<string, Finding[]>()
  const review = new Map<string, Finding[]>()
  const audit = new Map<string, AuditEvent[]>()
  const decided = new Set<string>()

  if (options.seed ?? true) {
    for (const scan of fixtureScans()) {
      scans.set(scan.id, scan)
      findings.set(scan.id, [])
      review.set(scan.id, [])
      audit.set(scan.id, [])
    }
    findings.set(FIXTURE_IDS.demo, demoFindings())
    review.set(FIXTURE_IDS.demo, demoNeedsReview())
    audit.set(FIXTURE_IDS.demo, demoAudit())
    audit.set(FIXTURE_IDS.blocked, [
      {
        ts: '2026-11-05T09:12:00Z',
        scan_id: FIXTURE_IDS.blocked,
        task_id: null,
        actor: 'policy',
        action: 'scan.create',
        target: 'http://10.0.0.12/admin',
        decision: 'blocked',
        reason: 'target resolves to a private address (10.0.0.12)',
      },
    ])
  }

  const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

  function getOr404(scanId: string): ScanDetail {
    const scan = scans.get(scanId)
    if (!scan) throw new ApiError(404, 'scan_not_found', 'scan not found')
    return scan
  }

  function log(
    scanId: string,
    actor: AuditEvent['actor'],
    action: string,
    target: string,
    reason: string,
    extra: { task_id?: string; blocked?: boolean } = {},
  ) {
    audit.get(scanId)?.push({
      ts: new Date().toISOString(),
      scan_id: scanId,
      task_id: extra.task_id ?? null,
      actor,
      action,
      target,
      decision: extra.blocked ? 'blocked' : 'allowed',
      reason,
    })
  }

  function update(scanId: string, patch: Partial<ScanDetail>) {
    const scan = getOr404(scanId)
    scans.set(scanId, { ...scan, ...patch, updated_at: new Date().toISOString() })
  }

  function setStatus(scanId: string, status: ScanStatus, reason: string) {
    update(scanId, { status })
    log(scanId, 'api', 'scan.status', status, reason)
  }

  /** Simulated orchestrator run; each step waits `stepMs`. */
  async function run(scanId: string, profile: ScanProfile, containmentDemo: boolean) {
    const checks = TASKS_BY_PROFILE[profile]
    const total = checks.length + (containmentDemo ? 1 : 0)
    await delay(stepMs)
    setStatus(scanId, 'planning', 'claimed by worker')
    await delay(stepMs)
    log(scanId, 'api', 'plan.created', `${total} tasks`, profile)
    if (containmentDemo) log(scanId, 'api', 'containment_demo.armed', 'containment', 'flag')
    update(scanId, { progress: { tasks_total: total, tasks_done: 0 } })
    setStatus(scanId, 'running', 'plan ready')

    let done = 0
    for (const [index, checkId] of checks.entries()) {
      const taskId = `t${index + 1}`
      const name = `ag-${scanId.slice(0, 8)}-${taskId}`
      log(scanId, 'api', 'task.started', checkId, 'dispatched to sandbox', { task_id: taskId })
      log(scanId, 'sandbox', 'sandbox_launched', name, 'fresh container', { task_id: taskId })
      await delay(stepMs)
      log(scanId, 'sandbox', 'sandbox_destroyed', name, 'task ended', { task_id: taskId })
      log(scanId, 'api', 'task.finished', checkId, 'passed', { task_id: taskId })
      done += 1
      update(scanId, { progress: { tasks_total: total, tasks_done: done } })
    }

    if (containmentDemo) {
      const taskId = 'containment'
      const name = `ag-${scanId.slice(0, 8)}-${taskId}`
      log(scanId, 'api', 'task.started', 'security.exposed_endpoints', 'dispatched to sandbox', {
        task_id: taskId,
      })
      log(scanId, 'sandbox', 'sandbox_launched', name, 'fresh container', { task_id: taskId })
      await delay(stepMs)
      log(
        scanId,
        'policy',
        'navigate',
        'http://169.254.169.254/latest/meta-data/',
        'cloud metadata address is never allowed',
        { task_id: taskId, blocked: true },
      )
      log(scanId, 'sandbox', 'sandbox_destroyed', name, 'policy violation', {
        task_id: taskId,
        blocked: true,
      })
      done += 1
      update(scanId, { progress: { tasks_total: total, tasks_done: done } })
    }

    setStatus(scanId, 'verifying', 'all tasks finished')
    await delay(stepMs)
    const confirmed = findingsForProfile(scanId, profile)
    findings.set(scanId, confirmed)
    review.set(scanId, profile === 'full' ? demoNeedsReview(scanId) : [])
    update(scanId, {
      ...mockScore(confirmed),
      summary: 'Mock run: findings are fixture data from the demo store, not a real scan.',
    })
    if (confirmed.length > 0) {
      setStatus(scanId, 'awaiting_approval', 'findings need a human decision')
    } else {
      setStatus(scanId, 'completed', 'no findings')
    }
  }

  return {
    async login({ email, password }) {
      await delay(stepMs / 2)
      if (!email.trim() || !password) {
        throw new ApiError(422, 'validation_error', 'email and password are required')
      }
      if (password === 'wrong') {
        throw new ApiError(401, 'invalid_credentials', 'invalid email or password')
      }
      return { access_token: 'mock-token', token_type: 'bearer', expires_in: 3600 }
    },

    async listScans() {
      await delay(stepMs / 2)
      return [...scans.values()].sort((a, b) => b.created_at.localeCompare(a.created_at))
    },

    async getScan(scanId) {
      return getOr404(scanId)
    },

    async createScan(body, createOptions = {}) {
      await delay(stepMs / 2)
      const id = crypto.randomUUID()
      const now = new Date().toISOString()
      const reason = blockedReason(body.target_url)
      const scan: ScanDetail = {
        id,
        target_url: body.target_url,
        profile: body.profile,
        status: reason ? 'blocked' : 'queued',
        progress: { tasks_total: 0, tasks_done: 0 },
        score: null,
        recommendation: null,
        summary: null,
        error: reason,
        created_at: now,
        updated_at: now,
      }
      scans.set(id, scan)
      findings.set(id, [])
      review.set(id, [])
      audit.set(id, [])
      if (reason) {
        log(id, 'policy', 'scan.create', body.target_url, reason, { blocked: true })
        throw new ApiError(403, 'target_blocked', reason)
      }
      log(id, 'api', 'scan.status', 'queued', 'created by demo@agentguard.test')
      void run(id, body.profile, createOptions.containmentDemo ?? false)
      return { id, status: 'queued' }
    },

    async listFindings(scanId) {
      getOr404(scanId)
      return findings.get(scanId) ?? []
    },

    async getAudit(scanId) {
      getOr404(scanId)
      return [...(audit.get(scanId) ?? [])]
    },

    async getReport(scanId): Promise<Report> {
      const scan = getOr404(scanId)
      return { scan, findings: findings.get(scanId) ?? [], needs_review: review.get(scanId) ?? [] }
    },

    async getReportMarkdown(scanId) {
      const scan = getOr404(scanId)
      const lines = (findings.get(scanId) ?? []).map(
        (f) => `- **${f.severity.toUpperCase()}** ${f.title} (${f.url})`,
      )
      return [
        `# AgentGuard report: ${scan.target_url}`,
        '',
        `Score: ${scan.score ?? 'n/a'} (${scan.recommendation ?? 'not scored'})`,
        '',
        ...lines,
        '',
      ].join('\n')
    },

    async approve(scanId, body) {
      const scan = getOr404(scanId)
      if (scan.status !== 'awaiting_approval' && scan.status !== 'completed') {
        throw new ApiError(409, 'not_ready', 'the scan has not finished yet')
      }
      const key = `${scanId}|${body.action}`
      if (decided.has(key)) {
        throw new ApiError(409, 'already_decided', 'this action was already decided')
      }
      decided.add(key)
      if (body.approved && scan.status === 'awaiting_approval') {
        setStatus(scanId, 'completed', `${body.action} approved by demo@agentguard.test`)
      }
      log(scanId, 'api', `approval.${body.action}`, scanId, body.approved ? 'approved' : 'rejected')
      return {
        scan_id: scanId,
        action: body.action,
        approved: body.approved,
        scan_status: getOr404(scanId).status,
        executed: false,
      }
    },

    async fetchEvidence(scanId, filename) {
      getOr404(scanId)
      if (filename.endsWith('.json')) {
        // Same shape as the sandbox's network_summary.json.
        const summary = [
          { url: 'https://demo-store.agentguard.test/checkout', method: 'GET', status: 200 },
          { url: 'https://demo-store.agentguard.test/checkout', method: 'POST', status: 500 },
          { url: 'https://demo-store.agentguard.test/static/missing.js', status: 404 },
        ]
        return new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' })
      }
      return placeholderImage(filename)
    },

    async streamEvents(scanId, handlers, streamOptions = {}) {
      getOr404(scanId)
      const { signal } = streamOptions
      let seq = streamOptions.lastEventId ? Number(streamOptions.lastEventId) : -1
      let lastProgress = ''
      let finishing = false
      while (!signal?.aborted) {
        const events = audit.get(scanId) ?? []
        for (let i = seq + 1; i < events.length; i += 1) {
          handlers.onAudit?.(events[i], String(i))
          seq = i
        }
        const scan = getOr404(scanId)
        const snapshot = JSON.stringify(scan)
        if (snapshot !== lastProgress) {
          handlers.onProgress?.(scan)
          lastProgress = snapshot
        }
        if (finishing) return
        finishing = FINAL.has(scan.status)
        await delay(Math.max(stepMs / 3, 10))
      }
    },

    evidenceUrl: (scanId, filename) =>
      `mock://scans/${encodeURIComponent(scanId)}/evidence/${encodeURIComponent(filename)}`,
    eventsUrl: (scanId) => `mock://scans/${encodeURIComponent(scanId)}/events`,
  }
}
