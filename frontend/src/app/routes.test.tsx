import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { describe, expect, it } from 'vitest'
import { ApiError, type ApiClient } from '../api/client'
import { createMockClient } from '../api/mock/mockClient'
import { AuthProvider } from '../auth/AuthProvider'
import { saveSession } from '../auth/session'
import { loginErrorMessage } from '../pages/loginErrors'
import { routes } from './routes'

function renderApp(path: string, client: ApiClient = createMockClient({ stepMs: 1 })) {
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  render(
    <AuthProvider createClient={() => client}>
      <RouterProvider router={router} />
    </AuthProvider>,
  )
  return router
}

describe('routing and sign-in', () => {
  it('redirects signed-out users to login, then back to where they were going', async () => {
    const router = renderApp('/scans/new')
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument()

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Email'), 'demo@agentguard.test')
    await user.type(screen.getByLabelText('Password'), 'demo')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('heading', { name: 'New scan' })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/scans/new')
  })

  it('validates empty fields without calling the API', async () => {
    let calls = 0
    const client = createMockClient({ stepMs: 1 })
    const spy: ApiClient = {
      ...client,
      login: (body) => {
        calls += 1
        return client.login(body)
      },
    }
    renderApp('/login', spy)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Sign in' }))
    expect(screen.getByText('Enter your email address.')).toBeInTheDocument()
    expect(screen.getByText('Enter your password.')).toBeInTheDocument()
    expect(screen.getByLabelText('Email')).toHaveAttribute('aria-invalid', 'true')
    expect(calls).toBe(0)
  })

  it('shows and hides the password', async () => {
    renderApp('/login')
    const user = userEvent.setup()
    const password = await screen.findByLabelText('Password')
    await user.type(password, 'secret-pass')
    expect(password).toHaveAttribute('type', 'password')
    await user.click(screen.getByRole('button', { name: 'Show password' }))
    expect(password).toHaveAttribute('type', 'text')
    expect(screen.getByRole('button', { name: 'Hide password' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    await user.click(screen.getByRole('button', { name: 'Hide password' }))
    expect(password).toHaveAttribute('type', 'password')
  })

  it('shows a clear error for wrong credentials and stays on login', async () => {
    renderApp('/login')
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Email'), 'demo@agentguard.test')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('don’t match')
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('shows the signed-in shell and signs out', async () => {
    saveSession({ token: 't', expiresAt: Date.now() + 60_000 })
    renderApp('/')
    expect(await screen.findByRole('heading', { name: 'Scans' })).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('ignores an expired stored session', async () => {
    saveSession({ token: 't', expiresAt: Date.now() - 1 })
    renderApp('/')
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('renders a 404 page for unknown routes', async () => {
    saveSession({ token: 't', expiresAt: Date.now() + 60_000 })
    renderApp('/nope')
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument()
  })
})

describe('loginErrorMessage', () => {
  it('maps API codes to actionable messages', () => {
    expect(loginErrorMessage(new ApiError(429, 'rate_limited', 'x'))).toMatch(/Too many/)
    expect(loginErrorMessage(new ApiError(0, 'network_error', 'x'))).toMatch(/Can’t reach/)
    expect(loginErrorMessage(new Error('boom'))).toMatch(/Something went wrong/)
  })
})
