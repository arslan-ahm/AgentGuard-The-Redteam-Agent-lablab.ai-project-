import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { beforeEach, describe, expect, it } from 'vitest'
import { ApiError, type ApiClient } from '../api/client'
import { FIXTURE_IDS } from '../api/mock/fixtures'
import { createMockClient } from '../api/mock/mockClient'
import { routes } from '../app/routes'
import { AuthProvider } from '../auth/AuthProvider'
import { saveSession } from '../auth/session'

function renderAt(path: string, client: ApiClient = createMockClient({ stepMs: 1 })) {
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  render(
    <AuthProvider createClient={() => client}>
      <RouterProvider router={router} />
    </AuthProvider>,
  )
  return router
}

beforeEach(() => {
  saveSession({ token: 't', expiresAt: Date.now() + 60_000 })
})

describe('dashboard', () => {
  it('lists scans with status, score and decision', async () => {
    renderAt('/')
    const table = await screen.findByRole('table')
    expect(within(table).getByText('demo-store.agentguard.test')).toBeInTheDocument()
    expect(within(table).getByText('Fix first')).toBeInTheDocument()
    expect(within(table).getByText('Safe to ship')).toBeInTheDocument()
    expect(within(table).getByText('Blocked')).toBeInTheDocument()
    expect(screen.getByText(/1 awaiting your approval/)).toBeInTheDocument()
  })

  it('shows an empty state with a call to action', async () => {
    renderAt('/', createMockClient({ stepMs: 1, seed: false }))
    expect(await screen.findByText('No scans yet')).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: /New scan/ }).length).toBeGreaterThan(0)
  })

  it('shows an error state with retry', async () => {
    const client = createMockClient({ stepMs: 1 })
    let fail = true
    const flaky: ApiClient = {
      ...client,
      listScans: () =>
        fail ? Promise.reject(new ApiError(0, 'network_error', 'down')) : client.listScans(),
    }
    renderAt('/', flaky)
    expect(await screen.findByText(/Can’t reach the AgentGuard server/)).toBeInTheDocument()
    fail = false
    await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByRole('table')).toBeInTheDocument()
  })
})

describe('new scan', () => {
  it('requires a valid URL and the authorization checkbox', async () => {
    renderAt('/scans/new')
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Start scan' }))
    expect(screen.getByText('Enter the URL of the site to test.')).toBeInTheDocument()
    expect(screen.getByText(/Confirm that you’re authorized/)).toBeInTheDocument()
  })

  it('starts a scan with the containment demo and opens its live view', async () => {
    const router = renderAt('/scans/new')
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Target URL'), 'https://shop.example.com')
    await user.click(screen.getByRole('radio', { name: /Security/ }))
    await user.click(screen.getByRole('checkbox', { name: /I own this site/ }))
    await user.click(screen.getByRole('checkbox', { name: /containment demo/ }))
    await user.click(screen.getByRole('button', { name: 'Start scan' }))

    expect(await screen.findByRole('heading', { name: 'shop.example.com' })).toBeInTheDocument()
    expect(router.state.location.pathname).toMatch(/^\/scans\/[0-9a-f-]+$/)
    // The simulated run reaches the containment block and the decision.
    expect(await screen.findByRole('heading', { name: 'Blocked by policy' })).toBeInTheDocument()
    expect(await screen.findByText(/Sandbox destroyed at/)).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /View report/ })).toBeInTheDocument()
  })

  it('explains a target blocked by the policy', async () => {
    renderAt('/scans/new')
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Target URL'), 'http://169.254.169.254/')
    await user.click(screen.getByRole('checkbox', { name: /I own this site/ }))
    await user.click(screen.getByRole('button', { name: 'Start scan' }))
    expect(
      await screen.findByText('This target is blocked by the safety policy'),
    ).toBeInTheDocument()
  })
})

describe('scan page', () => {
  it('shows the containment moment, findings and the activity log for the demo scan', async () => {
    renderAt(`/scans/${FIXTURE_IDS.demo}`)
    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Blocked by policy')).toBeInTheDocument()
    expect(within(alert).getByText('http://169.254.169.254/latest/meta-data/')).toBeInTheDocument()
    expect(within(alert).getByText(/Sandbox destroyed at/)).toBeInTheDocument()
    expect(await screen.findByText('Error response leaks internal stack trace')).toBeInTheDocument()
    expect(screen.getByText('Needs manual review')).toBeInTheDocument()
    expect(screen.getByText('Test plan created')).toBeInTheDocument()
  })

  it('filters findings by category', async () => {
    renderAt(`/scans/${FIXTURE_IDS.demo}`)
    await screen.findByText('Error response leaks internal stack trace')
    await userEvent.setup().click(screen.getByRole('button', { name: /Accessibility/ }))
    expect(screen.queryByText('Error response leaks internal stack trace')).not.toBeInTheDocument()
    expect(screen.getByText('Product images are missing alt text')).toBeInTheDocument()
  })

  it('records an approval and says plainly that nothing was sent', async () => {
    renderAt(`/scans/${FIXTURE_IDS.demo}`)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'GitHub issue' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/AgentGuard: Fix first/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }))
    expect(await within(dialog).findByText('Approved and recorded')).toBeInTheDocument()
    expect(within(dialog).getByText(/Nothing has been sent yet/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Done' }))
    expect(screen.getByRole('button', { name: 'GitHub issue: approved' })).toBeDisabled()
    expect(screen.getAllByText('Completed').length).toBeGreaterThan(0)
  })

  it('explains a scan blocked at creation', async () => {
    renderAt(`/scans/${FIXTURE_IDS.blocked}`)
    expect(await screen.findByText('Scan blocked before it started')).toBeInTheDocument()
    expect(screen.getByText('No tests ran.')).toBeInTheDocument()
  })
})

describe('finding and report pages', () => {
  it('shows a finding with reproduction steps, fix and evidence', async () => {
    renderAt(`/scans/${FIXTURE_IDS.demo}/findings/${FIXTURE_IDS.demo.slice(0, 8)}-f1`)
    expect(
      await screen.findByRole('heading', { name: 'Error response leaks internal stack trace' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Submit the form with an invalid coupon code')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Suggested fix' })).toBeInTheDocument()
    // Evidence has its own section tab; inside it, screenshot first, then the network summary.
    const user = userEvent.setup()
    await user.click(screen.getByRole('tab', { name: /Evidence/ }))
    await user.click(await screen.findByRole('tab', { name: 'Network summary' }))
    expect(await screen.findByRole('table', { name: /Requests captured/ })).toBeInTheDocument()
    expect(screen.getByText('POST')).toBeInTheDocument()
  })

  it('shows a not-found state for an unknown finding', async () => {
    renderAt(`/scans/${FIXTURE_IDS.demo}/findings/nope`)
    expect(await screen.findByText('Finding not found')).toBeInTheDocument()
  })

  it('shows the decision banner, severity counts and prioritized fixes', async () => {
    renderAt(`/scans/${FIXTURE_IDS.demo}/report`)
    const banner = await screen.findByRole('region', { name: 'Release decision' })
    expect(within(banner).getByText('Fix first')).toBeInTheDocument()
    expect(within(banner).getByText('60')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Prioritized fixes' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Markdown/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Save as PDF/ })).toBeInTheDocument()
  })

  it('does not show a report for a blocked scan', async () => {
    renderAt(`/scans/${FIXTURE_IDS.blocked}/report`)
    expect(await screen.findByText('The report isn’t ready')).toBeInTheDocument()
  })
})
