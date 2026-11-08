import { ArrowRight, AtSign, Box, Eye, EyeOff, Lock, ShieldOff, UserRound } from 'lucide-react'
import { useState, type FormEvent, type KeyboardEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { useAuth } from '../auth/context'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { TextField } from '../components/ui/TextField'
import { Wordmark } from '../components/Wordmark'
import { ScanShowcase } from '../features/auth/ScanShowcase'
import { loginErrorMessage } from './loginErrors'

interface FieldErrors {
  email?: string
  password?: string
}

function validate(email: string, password: string): FieldErrors {
  const errors: FieldErrors = {}
  if (!email.trim()) errors.email = 'Enter your email address.'
  else if (!/^\S+@\S+\.\S+$/.test(email.trim())) errors.email = 'Enter a valid email address.'
  if (!password) errors.password = 'Enter your password.'
  return errors
}

export function LoginPage() {
  const { isAuthenticated, sessionExpired, mockMode, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? '/'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [capsLock, setCapsLock] = useState(false)

  if (isAuthenticated && !submitting) return <Navigate to={from} replace />

  function trackCapsLock(event: KeyboardEvent<HTMLInputElement>) {
    setCapsLock(event.getModifierState?.('CapsLock') ?? false)
  }

  /** Mock mode only: any credentials work, so offer a one-click sign-in. */
  function fillDemoAccount() {
    setEmail('demo@agentguard.test')
    setPassword('demo-pass')
    setFieldErrors({})
    setFormError(null)
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const errors = validate(email, password)
    setFieldErrors(errors)
    setFormError(null)
    if (errors.email || errors.password) return
    setSubmitting(true)
    try {
      await login(email.trim(), password)
      navigate(from, { replace: true })
    } catch (error) {
      setFormError(loginErrorMessage(error))
      setSubmitting(false)
    }
  }

  return (
    <main className="grid min-h-dvh lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <div className="flex flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm">
          <Wordmark className="text-lg" />
          <p className="mt-3 text-base text-fg-muted">
            Test a site safely. See what’s broken, with proof.
          </p>

          <div className="mt-6 glass rounded-lg border border-glass-edge p-6 transition-[border-color,box-shadow] duration-200 focus-within:border-accent/40 focus-within:shadow-lift sm:p-8">
            <h1 className="text-xl font-semibold text-fg">Sign in</h1>
            <p className="mt-1 text-sm text-fg-muted">
              Run QA and security checks on sites you’re authorized to test.
            </p>

            {(sessionExpired || mockMode || formError) && (
              <div className="mt-5 flex flex-col gap-3">
                {sessionExpired && (
                  <Alert tone="info" title="Your session ended">
                    Sign in again to continue.
                  </Alert>
                )}
                {mockMode && (
                  <Alert tone="warning" title="Mock mode">
                    No backend is used. Any email and password work (use “wrong” to see an error).
                  </Alert>
                )}
                {formError && <Alert tone="error" title={formError} />}
              </div>
            )}

            <form noValidate onSubmit={onSubmit} className="mt-6 flex flex-col gap-4">
              <TextField
                label="Email"
                type="email"
                name="email"
                autoComplete="username"
                placeholder="you@company.com"
                icon={<AtSign aria-hidden="true" className="size-4" />}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                error={fieldErrors.email}
                required
              />
              <div className="flex flex-col gap-1.5">
                <TextField
                  label="Password"
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  autoComplete="current-password"
                  icon={<Lock aria-hidden="true" className="size-4" />}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={trackCapsLock}
                  onKeyUp={trackCapsLock}
                  onBlur={() => setCapsLock(false)}
                  error={fieldErrors.password}
                  trailing={
                    <button
                      type="button"
                      onClick={() => setShowPassword((v) => !v)}
                      aria-pressed={showPassword}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      title={showPassword ? 'Hide password' : 'Show password'}
                      className="inline-flex size-11 items-center justify-center rounded-md text-fg-muted transition-colors hover:text-fg"
                    >
                      {showPassword ? (
                        <EyeOff aria-hidden="true" className="size-4" />
                      ) : (
                        <Eye aria-hidden="true" className="size-4" />
                      )}
                    </button>
                  }
                  required
                />
                {capsLock && (
                  <p role="status" className="text-sm text-warn">
                    Caps Lock is on.
                  </p>
                )}
              </div>
              <Button type="submit" loading={submitting} className="mt-2 w-full">
                {submitting ? 'Signing in…' : 'Sign in'}
                {!submitting && <ArrowRight aria-hidden="true" className="size-4" />}
              </Button>
              {mockMode && (
                <Button
                  variant="secondary"
                  onClick={fillDemoAccount}
                  disabled={submitting}
                  icon={<UserRound aria-hidden="true" className="size-4" />}
                  className="w-full"
                >
                  Use demo account
                </Button>
              )}
            </form>
          </div>

          <p className="mt-6 flex items-start gap-2 text-sm text-fg-muted">
            <Lock aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-accent" />
            Scans run in a sealed sandbox. Nothing is sent without your approval.
          </p>
          <ul className="mt-4 flex flex-wrap gap-x-5 gap-y-2">
            <li className="label-mono inline-flex items-center gap-1.5 text-fg-muted">
              <Box aria-hidden="true" className="size-3.5 text-accent" />
              Disposable Docker sandbox
            </li>
            <li className="label-mono inline-flex items-center gap-1.5 text-fg-muted">
              <ShieldOff aria-hidden="true" className="size-3.5 text-accent" />
              Private networks blocked
            </li>
          </ul>
        </div>
      </div>

      <aside aria-label="How a scan runs" className="hidden border-l border-line lg:block">
        <ScanShowcase />
      </aside>
    </main>
  )
}
