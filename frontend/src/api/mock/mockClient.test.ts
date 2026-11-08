import { describe, expect, it } from 'vitest'
import type { AuditEvent } from '../contracts'
import { RECOMMENDATIONS, SCAN_STATUSES, SEVERITIES } from '../contracts'
import type { ScanDetail } from '../schemas'
import { FIXTURE_IDS } from './fixtures'
import { createMockClient } from './mockClient'

describe('createMockClient', () => {
  it('rejects the "wrong" password with the backend error code', async () => {
    const client = createMockClient({ stepMs: 1 })
    await expect(client.login({ email: 'a@b.test', password: 'wrong' })).rejects.toMatchObject({
      status: 401,
      code: 'invalid_credentials',
    })
    await expect(client.login({ email: 'a@b.test', password: 'x' })).resolves.toMatchObject({
      token_type: 'bearer',
    })
  })

  it('seeds fixture scans that match the contracts', async () => {
    const scans = await createMockClient({ stepMs: 1 }).listScans()
    expect(scans.length).toBeGreaterThan(0)
    for (const scan of scans) expect(SCAN_STATUSES).toContain(scan.status)

    const report = await createMockClient({ stepMs: 1 }).getReport(FIXTURE_IDS.demo)
    for (const f of report.findings) {
      expect(SEVERITIES).toContain(f.severity)
      expect(f.scan_id).toBe(FIXTURE_IDS.demo)
      expect(f.confidence).toBeGreaterThanOrEqual(0.5)
    }
    for (const f of report.needs_review) expect(f.confidence).toBeLessThan(0.5)
    expect(report.scan.score).toBe(60)
    expect(report.scan.recommendation).toBe(RECOMMENDATIONS.fixFirst)
  })

  it('blocks private targets with 403 target_blocked and records a blocked audit event', async () => {
    const client = createMockClient({ stepMs: 1 })
    await expect(
      client.createScan({
        target_url: 'http://169.254.169.254/',
        profile: 'security',
        authorized: true,
      }),
    ).rejects.toMatchObject({ status: 403, code: 'target_blocked' })
    const blocked = (await client.listScans()).find((s) => s.target_url.includes('169.254'))
    expect(blocked?.status).toBe('blocked')
  })

  it('runs a scan to awaiting_approval and streams the containment block', async () => {
    const client = createMockClient({ stepMs: 2, seed: false })
    const { id } = await client.createScan(
      { target_url: 'https://shop.example.com', profile: 'full', authorized: true },
      { containmentDemo: true },
    )
    const audit: AuditEvent[] = []
    const statuses: ScanDetail['status'][] = []
    await client.streamEvents(id, {
      onAudit: (event) => audit.push(event),
      onProgress: (scan) => statuses.push(scan.status),
    })

    expect(statuses.at(-1)).toBe('awaiting_approval')
    expect(statuses).toContain('running')
    const blocked = audit.filter((e) => e.decision === 'blocked').map((e) => e.action)
    expect(blocked).toEqual(['navigate', 'sandbox_destroyed'])
    const scan = await client.getScan(id)
    expect(scan.progress.tasks_done).toBe(scan.progress.tasks_total)
    expect(scan.score).toBe(60)
  })

  it('records approvals once and completes the scan', async () => {
    const client = createMockClient({ stepMs: 1 })
    const result = await client.approve(FIXTURE_IDS.demo, {
      action: 'github_issue',
      approved: true,
    })
    expect(result).toMatchObject({ scan_status: 'completed', executed: false })
    await expect(
      client.approve(FIXTURE_IDS.demo, { action: 'github_issue', approved: true }),
    ).rejects.toMatchObject({ status: 409, code: 'already_decided' })
  })

  it('answers 404 scan_not_found for unknown scans', async () => {
    await expect(createMockClient({ stepMs: 1 }).getScan('nope')).rejects.toMatchObject({
      status: 404,
      code: 'scan_not_found',
    })
  })
})
