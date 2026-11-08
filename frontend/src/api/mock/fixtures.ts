/**
 * Fixture data for mock mode (`bun run dev:mock`) and component tests.
 *
 * Shaped exactly like the API responses (contracts.ts + schemas.ts) and modelled on the flawed
 * demo store in `scripts/demo-store/`. Not real scan output: never use it for screenshots or
 * numbers in the deck, video or README.
 */

import type { AuditEvent, Finding } from '../contracts'
import type { ScanDetail } from '../schemas'

export const DEMO_TARGET = 'https://demo-store.agentguard.test'

const DEMO_SCAN_ID = '8f14e45f-ceea-4e7a-9b3f-2d5c1a0b7e61'
const SAFE_SCAN_ID = '1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f'
const BLOCKED_SCAN_ID = '9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d'

/** Findings of the completed demo-store scan (score 60: 2 high, 3 medium, 1 low). */
export function demoFindings(scanId: string = DEMO_SCAN_ID): Finding[] {
  const finding = (id: string, rest: Omit<Finding, 'id' | 'scan_id'>): Finding => ({
    id: `${scanId.slice(0, 8)}-${id}`,
    scan_id: scanId,
    ...rest,
  })
  return [
    finding('f1', {
      title: 'Error response leaks internal stack trace',
      category: 'security',
      severity: 'high',
      confidence: 0.94,
      url: `${DEMO_TARGET}/checkout`,
      evidence: ['t4__checkout_error.png', 't4__network_summary.json'],
      reproduction: [
        'Open /checkout',
        'Submit the form with an invalid coupon code',
        'Observe the HTTP 500 response with a Python stack trace',
      ],
      impact: 'Attackers can learn internal file paths, framework versions and code structure.',
      recommended_fix:
        'Return a generic error page, log details server-side, and disable debug mode in production.',
      check_id: 'security.error_leak',
      verified: true,
    }),
    finding('f2', {
      title: 'Checkout fails for a valid order',
      category: 'qa',
      severity: 'high',
      confidence: 0.91,
      url: `${DEMO_TARGET}/checkout`,
      evidence: ['t3__checkout_submit.png', 't3__network_summary.json'],
      reproduction: [
        'Add any product to the cart',
        'Open /checkout and fill in valid details',
        'Click "Place order"; the request returns HTTP 500 and no confirmation appears',
      ],
      impact: 'Customers cannot complete purchases, which directly loses revenue.',
      recommended_fix:
        'Fix the order handler error and add an end-to-end checkout test to the release pipeline.',
      check_id: 'qa.checkout',
      verified: true,
    }),
    finding('f3', {
      title: 'Content-Security-Policy header is missing',
      category: 'security',
      severity: 'medium',
      confidence: 0.99,
      url: `${DEMO_TARGET}/`,
      evidence: ['t5__network_summary.json'],
      reproduction: ['Request /', 'Inspect the response headers: no Content-Security-Policy'],
      impact: 'Injected scripts are not restricted, which makes cross-site scripting easier.',
      recommended_fix:
        "Send a Content-Security-Policy header, starting with default-src 'self' and tightening per page.",
      check_id: 'security.headers',
      verified: true,
    }),
    finding('f4', {
      title: 'Session cookie set without Secure and HttpOnly',
      category: 'security',
      severity: 'medium',
      confidence: 0.97,
      url: `${DEMO_TARGET}/login`,
      evidence: ['t6__network_summary.json'],
      reproduction: ['Open /login', 'Inspect the Set-Cookie header of the session cookie'],
      impact: 'The session cookie can be read by scripts and sent over plain HTTP.',
      recommended_fix: 'Set the session cookie with Secure, HttpOnly and SameSite=Lax.',
      check_id: 'security.cookies',
      verified: true,
    }),
    finding('f5', {
      title: 'Contact form shows no confirmation after submit',
      category: 'qa',
      severity: 'medium',
      confidence: 0.86,
      url: `${DEMO_TARGET}/contact`,
      evidence: ['t2__contact_after_submit.png'],
      reproduction: [
        'Open /contact',
        'Fill in name, email and message with valid values',
        'Click "Send"; the page reloads with no success or error message',
      ],
      impact: 'Visitors cannot tell whether their message was sent and may give up.',
      recommended_fix: 'Show a clear success message after submit and an error state on failure.',
      check_id: 'qa.forms',
      verified: true,
    }),
    finding('f6', {
      title: 'Product images are missing alt text',
      category: 'accessibility',
      severity: 'low',
      confidence: 0.98,
      url: `${DEMO_TARGET}/products`,
      evidence: ['t1__products.png'],
      reproduction: ['Open /products', 'Inspect the product <img> elements: no alt attribute'],
      impact: 'Screen-reader users cannot tell what the products are.',
      recommended_fix: 'Add a short, descriptive alt attribute to every product image.',
      check_id: 'qa.accessibility',
      verified: true,
    }),
  ]
}

/** Low-confidence finding the verifier parked for manual review (excluded from the score). */
export function demoNeedsReview(scanId: string = DEMO_SCAN_ID): Finding[] {
  return [
    {
      id: `${scanId.slice(0, 8)}-r1`,
      scan_id: scanId,
      title: 'Possible reflected input on the search page',
      category: 'security',
      severity: 'medium',
      confidence: 0.42,
      url: `${DEMO_TARGET}/search?q=agentguard-probe-${scanId.slice(0, 8)}`,
      evidence: ['t7__search_probe.png'],
      reproduction: ['Search for the marked probe value', 'The value appears in the page HTML'],
      impact: 'If unescaped, reflected input could allow cross-site scripting.',
      recommended_fix: 'Confirm the value is HTML-escaped wherever search terms are rendered.',
      check_id: 'security.reflected_input',
      verified: false,
    },
  ]
}

function event(
  scanId: string,
  ts: string,
  actor: AuditEvent['actor'],
  action: string,
  target: string,
  reason: string,
  extra: { task_id?: string; blocked?: boolean } = {},
): AuditEvent {
  return {
    ts,
    scan_id: scanId,
    task_id: extra.task_id ?? null,
    actor,
    action,
    target,
    decision: extra.blocked ? 'blocked' : 'allowed',
    reason,
  }
}

/** Audit trail of the demo scan, including the containment moment (blocked metadata request). */
export function demoAudit(scanId: string = DEMO_SCAN_ID, day = '2026-11-06'): AuditEvent[] {
  const at = (time: string) => `${day}T${time}Z`
  return [
    event(
      scanId,
      at('10:00:00'),
      'api',
      'scan.status',
      'queued',
      'created by demo@agentguard.test; authorization attested',
    ),
    event(scanId, at('10:00:01'), 'api', 'scan.status', 'planning', 'claimed by worker'),
    event(scanId, at('10:00:04'), 'api', 'plan.created', '7 tasks', 'full'),
    event(scanId, at('10:00:04'), 'api', 'scan.status', 'running', 'plan ready'),
    event(scanId, at('10:00:05'), 'api', 'task.started', 'qa.checkout', 'dispatched to sandbox', {
      task_id: 't3',
    }),
    event(scanId, at('10:00:05'), 'sandbox', 'sandbox_launched', 'ag-t3', 'fresh container', {
      task_id: 't3',
    }),
    event(scanId, at('10:00:19'), 'sandbox', 'sandbox_destroyed', 'ag-t3', 'task ended', {
      task_id: 't3',
    }),
    event(scanId, at('10:00:19'), 'api', 'task.finished', 'qa.checkout', 'failed: 1 finding', {
      task_id: 't3',
    }),
    event(scanId, at('10:00:20'), 'sandbox', 'sandbox_launched', 'ag-t8', 'fresh container', {
      task_id: 't8',
    }),
    event(
      scanId,
      at('10:00:23'),
      'policy',
      'navigate',
      'http://169.254.169.254/latest/meta-data/',
      'cloud metadata address is never allowed',
      { task_id: 't8', blocked: true },
    ),
    event(scanId, at('10:00:23'), 'sandbox', 'sandbox_destroyed', 'ag-t8', 'policy violation', {
      task_id: 't8',
      blocked: true,
    }),
    event(scanId, at('10:01:40'), 'api', 'scan.status', 'verifying', 'all tasks finished'),
    event(
      scanId,
      at('10:01:52'),
      'api',
      'scan.status',
      'awaiting_approval',
      'findings need a human decision',
    ),
  ]
}

export function fixtureScans(): ScanDetail[] {
  return [
    {
      id: DEMO_SCAN_ID,
      target_url: DEMO_TARGET,
      profile: 'full',
      status: 'awaiting_approval',
      progress: { tasks_total: 8, tasks_done: 8 },
      score: 60,
      recommendation: 'Fix high-priority issues before release',
      summary:
        'Checkout is broken and an error page leaks a stack trace. Fix both before release; the header and cookie issues are quick wins.',
      error: null,
      created_at: '2026-11-06T10:00:00Z',
      updated_at: '2026-11-06T10:01:52Z',
    },
    {
      id: SAFE_SCAN_ID,
      target_url: 'https://docs.agentguard.test',
      profile: 'smoke',
      status: 'completed',
      progress: { tasks_total: 4, tasks_done: 4 },
      score: 94,
      recommendation: 'Safe to ship with monitoring',
      summary:
        'Pages load and links work. One missing Referrer-Policy header and an image without alt text.',
      error: null,
      created_at: '2026-11-05T15:20:00Z',
      updated_at: '2026-11-05T15:21:10Z',
    },
    {
      id: BLOCKED_SCAN_ID,
      target_url: 'http://10.0.0.12/admin',
      profile: 'security',
      status: 'blocked',
      progress: { tasks_total: 0, tasks_done: 0 },
      score: null,
      recommendation: null,
      summary: null,
      error: 'target resolves to a private address (10.0.0.12)',
      created_at: '2026-11-05T09:12:00Z',
      updated_at: '2026-11-05T09:12:00Z',
    },
  ]
}

export const FIXTURE_IDS = { demo: DEMO_SCAN_ID, safe: SAFE_SCAN_ID, blocked: BLOCKED_SCAN_ID }
