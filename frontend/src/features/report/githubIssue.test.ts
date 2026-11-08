import { describe, expect, it } from 'vitest'
import type { Finding } from '../../api/contracts'
import { demoFindings, fixtureScans } from '../../api/mock/fixtures'
import { githubIssueBody, githubIssueTitle } from './githubIssue'

const scan = fixtureScans()[0]

describe('GitHub issue template', () => {
  it('titles the issue with the decision, host and score', () => {
    expect(githubIssueTitle(scan)).toBe(
      'AgentGuard: Fix first for demo-store.agentguard.test (score 60/100)',
    )
  })

  it('lists findings most severe first with steps and fixes', () => {
    const body = githubIssueBody(scan, demoFindings())
    expect(body).toContain('| Severity | Finding | Category | Confidence |')
    expect(body.indexOf('### High')).toBeLessThan(body.indexOf('### Low'))
    expect(body).toContain('1. Open /checkout')
    expect(body).toContain('**Suggested fix:**')
    expect(body).toContain('filed only after human approval')
  })

  it('neutralises table pipes, newlines and @mentions from target-controlled text', () => {
    const hostile: Finding = {
      ...demoFindings()[0],
      title: 'Bad | title\nwith @team mention',
    }
    const body = githubIssueBody(scan, [hostile])
    expect(body).toContain('Bad \\| title with @​team mention')
    expect(body).not.toContain('@team')
  })

  it('handles a scan without findings', () => {
    expect(githubIssueBody(scan, [])).toContain('No verified findings.')
  })
})
