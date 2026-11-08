import { describe, expect, it } from 'vitest'
import type { AuditEvent } from '../api/contracts'
import { RECOMMENDATIONS } from '../api/contracts'
import { demoFindings } from '../api/mock/fixtures'
import { evidenceLabel, parseNetworkSummary } from '../features/evidence/networkSummary'
import {
  checkLabel,
  countBySeverity,
  decisionOf,
  describeEvent,
  isPolicyBlock,
  sortFindings,
} from './format'
import { validateTargetUrl } from './validation'

const event = (patch: Partial<AuditEvent>): AuditEvent => ({
  ts: '2026-11-07T10:00:00Z',
  scan_id: 's1',
  task_id: 't1',
  actor: 'sandbox',
  action: 'sandbox_launched',
  target: 'ag-t1',
  decision: 'allowed',
  reason: 'fresh container',
  ...patch,
})

describe('decisionOf', () => {
  it('prefers the backend recommendation text', () => {
    expect(decisionOf(95, RECOMMENDATIONS.block)).toBe('block')
    expect(decisionOf(10, RECOMMENDATIONS.safe)).toBe('safe')
  })

  it('falls back to the brief 5.10 score bands at their edges', () => {
    expect(decisionOf(49, null)).toBe('block')
    expect(decisionOf(50, null)).toBe('fixFirst')
    expect(decisionOf(79, null)).toBe('fixFirst')
    expect(decisionOf(80, null)).toBe('safe')
    expect(decisionOf(null, null)).toBeNull()
  })
})

describe('findings helpers', () => {
  it('sorts by severity, then confidence', () => {
    const sorted = sortFindings(demoFindings())
    expect(sorted.map((f) => f.severity)).toEqual([
      'high',
      'high',
      'medium',
      'medium',
      'medium',
      'low',
    ])
    expect(sorted[0].confidence).toBeGreaterThanOrEqual(sorted[1].confidence)
  })

  it('counts by severity', () => {
    expect(countBySeverity(demoFindings())).toEqual({ critical: 0, high: 2, medium: 3, low: 1 })
  })

  it('labels known checks and passes unknown ids through', () => {
    expect(checkLabel('security.error_leak')).toBe('Error detail leak')
    expect(checkLabel('qa.custom')).toBe('qa.custom')
  })
})

describe('audit events', () => {
  it('describes the containment moment', () => {
    const blocked = event({
      actor: 'policy',
      action: 'navigate',
      target: 'http://169.254.169.254/',
      decision: 'blocked',
      reason: 'metadata',
    })
    expect(describeEvent(blocked).title).toBe('Blocked by policy')
    expect(isPolicyBlock(blocked)).toBe(true)
    expect(isPolicyBlock(event({ action: 'sandbox_destroyed', decision: 'blocked' }))).toBe(false)
  })

  it('describes status changes and unknown actions', () => {
    expect(describeEvent(event({ action: 'scan.status', target: 'awaiting_approval' })).title).toBe(
      'Status: Awaiting approval',
    )
    expect(describeEvent(event({ action: 'something.new' })).title).toBe('something.new')
  })
})

describe('validateTargetUrl', () => {
  it('accepts http(s) URLs and rejects the rest with a reason', () => {
    expect(validateTargetUrl('https://staging.example.com')).toBeNull()
    expect(validateTargetUrl('  ')).toMatch(/Enter the URL/)
    expect(validateTargetUrl('example.com')).toMatch(/full URL/)
    expect(validateTargetUrl('ftp://example.com')).toMatch(/http/)
    expect(validateTargetUrl('https://user:pw@example.com')).toMatch(/username/)
  })
})

describe('network summary', () => {
  it('parses the sandbox format', () => {
    const raw = JSON.stringify([
      { url: 'https://x.test/', status: 200, headers: { server: 'x' } },
      { url: 'https://x.test/a', method: 'post', status: null, error: 'timeout' },
    ])
    expect(parseNetworkSummary(raw)).toEqual([
      { url: 'https://x.test/', method: 'GET', status: 200, error: undefined },
      { url: 'https://x.test/a', method: 'POST', status: null, error: 'timeout' },
    ])
  })

  it('returns null for anything else', () => {
    expect(parseNetworkSummary('not json')).toBeNull()
    expect(parseNetworkSummary('{"requests": []}')).toBeNull()
    expect(parseNetworkSummary('[{"status": 200}]')).toBeNull()
  })

  it('strips the task prefix from evidence names', () => {
    expect(evidenceLabel('t4__checkout_error.png')).toBe('checkout_error.png')
    expect(evidenceLabel('plain.png')).toBe('plain.png')
  })
})
