/** Display helpers. Pure functions: no API calls, no business rules beyond brief 5.10 labels. */

import type { AuditEvent, Finding, ScanProfile, ScanStatus, Severity } from '../api/contracts'
import { RECOMMENDATIONS, SEVERITIES } from '../api/contracts'

export const PROFILE_LABELS: Record<ScanProfile, string> = {
  smoke: 'Smoke',
  qa: 'QA',
  security: 'Security',
  full: 'Full audit',
}

export const STATUS_LABELS: Record<ScanStatus, string> = {
  queued: 'Queued',
  planning: 'Planning',
  running: 'Running',
  verifying: 'Verifying',
  awaiting_approval: 'Awaiting approval',
  completed: 'Completed',
  failed: 'Failed',
  blocked: 'Blocked',
}

/** Statuses after which the backend stops working on a scan (and closes the event stream). */
export const FINAL_STATUSES: ReadonlySet<ScanStatus> = new Set([
  'awaiting_approval',
  'completed',
  'failed',
  'blocked',
])

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export const CATEGORY_LABELS: Record<Finding['category'], string> = {
  qa: 'QA',
  security: 'Security',
  accessibility: 'Accessibility',
}

const CHECK_LABELS: Record<string, string> = {
  'qa.pages_load': 'Pages load',
  'qa.links_assets': 'Links and assets',
  'qa.forms': 'Forms',
  'qa.login': 'Login',
  'qa.password_reset': 'Password reset',
  'qa.search': 'Search',
  'qa.checkout': 'Checkout',
  'qa.console_network_errors': 'Console and network errors',
  'qa.accessibility': 'Accessibility basics',
  'security.https_redirect': 'HTTPS redirect',
  'security.headers': 'Security headers',
  'security.cookies': 'Cookie flags',
  'security.url_session_leak': 'Session token in URL',
  'security.error_leak': 'Error detail leak',
  'security.open_redirect': 'Open redirect',
  'security.reflected_input': 'Reflected input',
  'security.exposed_endpoints': 'Exposed admin/debug endpoints',
  'security.login_rate_probe': 'Login rate limit',
}

/** Human name of a check id, falling back to the id itself. */
export function checkLabel(checkId: string): string {
  return CHECK_LABELS[checkId] ?? checkId
}

export type Decision = 'block' | 'fixFirst' | 'safe'

export const DECISION_LABELS: Record<Decision, string> = {
  block: 'Block release',
  fixFirst: 'Fix first',
  safe: 'Safe to ship',
}

/**
 * Which decision band a scan is in. Uses the backend's recommendation text when it matches
 * brief 5.10, otherwise the 5.10 score bands. Never recomputes the score itself.
 */
export function decisionOf(score?: number | null, recommendation?: string | null): Decision | null {
  if (recommendation === RECOMMENDATIONS.block) return 'block'
  if (recommendation === RECOMMENDATIONS.fixFirst) return 'fixFirst'
  if (recommendation === RECOMMENDATIONS.safe) return 'safe'
  if (score === null || score === undefined) return null
  if (score < 50) return 'block'
  if (score < 80) return 'fixFirst'
  return 'safe'
}

/** Findings sorted most severe first, then by confidence (stable for equal keys). */
export function sortFindings(findings: Finding[]): Finding[] {
  const rank = (s: Severity) => SEVERITIES.indexOf(s)
  return [...findings].sort(
    (a, b) => rank(a.severity) - rank(b.severity) || b.confidence - a.confidence,
  )
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings) counts[f.severity] += 1
  return counts
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

/** Path + query of a URL, for compact display next to the host. */
export function pathOf(url: string): string {
  try {
    const u = new URL(url)
    return `${u.pathname}${u.search}`
  } catch {
    return url
  }
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const timeOnly = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
})

export function formatDateTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : dateTime.format(d)
}

export function formatTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : timeOnly.format(d)
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`
}

/** Plain-language description of an audit event, for the activity feed. */
export function describeEvent(event: AuditEvent): { title: string; detail: string } {
  const blocked = event.decision === 'blocked'
  switch (event.action) {
    case 'scan.status':
      return {
        title: `Status: ${STATUS_LABELS[event.target as ScanStatus] ?? event.target}`,
        detail: event.reason,
      }
    case 'scan.create':
      return blocked
        ? { title: 'Target blocked by policy', detail: `${event.target} · ${event.reason}` }
        : { title: 'Scan created', detail: event.target }
    case 'plan.created':
      return { title: 'Test plan created', detail: `${event.target} · profile ${event.reason}` }
    case 'containment_demo.armed':
      return { title: 'Containment demo armed', detail: 'An unsafe request will be attempted' }
    case 'task.started':
      return { title: `Task started: ${checkLabel(event.target)}`, detail: event.reason }
    case 'task.finished':
      return { title: `Task finished: ${checkLabel(event.target)}`, detail: event.reason }
    case 'task.error':
      return { title: `Task error: ${checkLabel(event.target)}`, detail: event.reason }
    case 'sandbox_launched':
      return { title: 'Sandbox launched', detail: `${event.target} · ${event.reason}` }
    case 'sandbox_destroyed':
      return { title: 'Sandbox destroyed', detail: `${event.target} · ${event.reason}` }
    case 'timeout_kill':
      return { title: 'Sandbox killed: time limit', detail: event.target }
    case 'navigate':
    case 'launch':
      return blocked
        ? { title: 'Blocked by policy', detail: `${event.target} · ${event.reason}` }
        : { title: 'Request allowed', detail: event.target }
    default:
      if (event.action.startsWith('approval.')) {
        return { title: 'Approval decision recorded', detail: `${event.action} · ${event.reason}` }
      }
      return { title: event.action, detail: `${event.target} · ${event.reason}` }
  }
}

/** True for the events that make up the containment moment (brief 6.1). */
export function isPolicyBlock(event: AuditEvent): boolean {
  return event.decision === 'blocked' && (event.action === 'navigate' || event.action === 'launch')
}
