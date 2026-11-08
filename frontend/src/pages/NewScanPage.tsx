import {
  Box,
  CircleCheck,
  CircleDashed,
  Globe,
  Layers,
  ListChecks,
  Play,
  ShieldHalf,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { useId, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { Breadcrumbs } from '../components/Breadcrumbs'
import { ApiError } from '../api/client'
import { SCAN_PROFILES, type ScanProfile } from '../api/contracts'
import { useApi } from '../auth/context'
import { AsideCard, SplitLayout } from '../components/SplitLayout'
import { PageHeader } from '../components/states'
import { Alert } from '../components/ui/Alert'
import { Button } from '../components/ui/Button'
import { buttonClasses } from '../components/ui/buttonStyles'
import { TextField } from '../components/ui/TextField'
import { hostOf, PROFILE_LABELS } from '../lib/format'
import { validateTargetUrl } from '../lib/validation'

const PROFILE_ICONS: Record<ScanProfile, LucideIcon> = {
  smoke: Zap,
  qa: ListChecks,
  security: ShieldHalf,
  full: Layers,
}

const PROFILE_HELP: Record<ScanProfile, string> = {
  smoke: 'Quick health check: pages load, links and assets, console errors, headers.',
  qa: 'Forms, login, password reset, search, checkout and accessibility basics.',
  security:
    'Safe security checks: HTTPS, headers, cookies, error leaks, open redirects, exposed endpoints.',
  full: 'Every QA and security check. Recommended before a release.',
}

/** What every scan does, in order (brief 6). */
const NEXT_STEPS = [
  { title: 'Plan', detail: 'The agent turns the profile into a list of test tasks.' },
  { title: 'Run', detail: 'Each task runs in its own fresh, locked-down sandbox.' },
  { title: 'Verify', detail: 'Findings are re-checked and scored out of 100.' },
  { title: 'Approve', detail: 'Nothing leaves AgentGuard until you approve it.' },
]

function PreviewRow({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  const Icon = ok ? CircleCheck : CircleDashed
  return (
    <div className="flex items-start justify-between gap-3">
      <dt className="text-fg-muted">{label}</dt>
      <dd
        className={`flex min-w-0 items-center gap-1.5 text-right ${ok ? 'text-fg' : 'text-fg-muted'}`}
      >
        <span className="truncate">{value}</span>
        <Icon
          aria-hidden="true"
          className={`size-4 shrink-0 ${ok ? 'text-success' : 'text-fg-muted'}`}
        />
      </dd>
    </div>
  )
}

interface SubmitError {
  title: string
  detail?: string
  /** Shown under the URL field instead of above the form. */
  onUrl?: boolean
}

function submitError(error: unknown): SubmitError {
  if (!(error instanceof ApiError)) return { title: 'Something went wrong. Please try again.' }
  switch (error.code) {
    case 'target_blocked':
      return {
        title: 'This target is blocked by the safety policy',
        detail: `${error.message}. Private and local addresses can’t be scanned. The attempt was recorded in the audit log.`,
        onUrl: true,
      }
    case 'rate_limited':
      return { title: 'Scan limit reached', detail: `${error.message}. Try again later.` }
    case 'network_error':
    case 'timeout':
      return { title: 'Can’t reach the AgentGuard server. Check your connection and try again.' }
    default:
      return { title: error.message || `Request failed (${error.code}).` }
  }
}

export function NewScanPage() {
  const api = useApi()
  const navigate = useNavigate()
  const groupId = useId()

  const [targetUrl, setTargetUrl] = useState('')
  const [profile, setProfile] = useState<ScanProfile>('full')
  const [authorized, setAuthorized] = useState(false)
  const [containmentDemo, setContainmentDemo] = useState(false)
  const [urlError, setUrlError] = useState<string | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
  const [error, setError] = useState<SubmitError | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    const urlProblem = validateTargetUrl(targetUrl)
    const authProblem = authorized ? null : 'Confirm that you’re authorized to test this site.'
    setUrlError(urlProblem)
    setAuthError(authProblem)
    setError(null)
    if (urlProblem || authProblem) return

    setSubmitting(true)
    try {
      const created = await api.createScan(
        { target_url: targetUrl.trim(), profile },
        { containmentDemo },
      )
      navigate(`/scans/${created.id}`)
    } catch (caught) {
      setError(submitError(caught))
      setSubmitting(false)
    }
  }

  const errorAlert = error && (
    <Alert tone="error" title={error.title}>
      {error.detail}
    </Alert>
  )

  const urlReady = validateTargetUrl(targetUrl) === null
  const aside = (
    <>
      <AsideCard title="Scan preview">
        <dl className="flex flex-col gap-3 text-sm" aria-live="polite">
          <PreviewRow
            label="Target"
            value={urlReady ? hostOf(targetUrl.trim()) : 'Not set'}
            ok={urlReady}
          />
          <PreviewRow label="Profile" value={PROFILE_LABELS[profile]} ok />
          <PreviewRow
            label="Containment demo"
            value={containmentDemo ? 'Included' : 'Off'}
            ok={containmentDemo}
          />
          <PreviewRow
            label="Authorization"
            value={authorized ? 'Confirmed' : 'Required'}
            ok={authorized}
          />
        </dl>
      </AsideCard>
      <AsideCard title="What happens next">
        <ol className="flex flex-col gap-4">
          {NEXT_STEPS.map((step, index) => (
            <li key={step.title} className="flex gap-3">
              <span
                aria-hidden="true"
                className="flex size-6 shrink-0 items-center justify-center rounded-full bg-raised font-mono text-xs text-accent"
              >
                {index + 1}
              </span>
              <span className="flex flex-col gap-0.5">
                <span className="text-sm font-medium text-fg">{step.title}</span>
                <span className="text-sm text-fg-muted">{step.detail}</span>
              </span>
            </li>
          ))}
        </ol>
      </AsideCard>
    </>
  )

  return (
    <section aria-labelledby="page-title" className="flex flex-col gap-6">
      <Breadcrumbs items={[{ label: 'Scans', to: '/' }, { label: 'New scan' }]} />
      <PageHeader
        title={<span id="page-title">New scan</span>}
        description="AgentGuard plans the tests, runs them in disposable sandboxes and returns findings with evidence."
        actions={
          <span className="label-mono inline-flex items-center gap-1.5 text-accent">
            <Box aria-hidden="true" className="size-3.5" />
            Disposable sandbox
          </span>
        }
      />

      <SplitLayout aside={aside} asideLabel="Scan preview">
        {error && !error.onUrl && errorAlert}

        <form noValidate onSubmit={onSubmit} className="flex flex-col gap-8">
          <div className="flex flex-col gap-3">
            <TextField
              label="Target URL"
              type="url"
              name="target_url"
              inputMode="url"
              autoComplete="url"
              spellCheck={false}
              placeholder="https://staging.example.com"
              hint="A public http(s) address. Private, internal and cloud-metadata addresses are refused."
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              error={urlError}
              icon={<Globe aria-hidden="true" className="size-4" />}
              className="[&_input]:font-mono"
              required
            />
            {error?.onUrl && errorAlert}
          </div>

          <fieldset>
            <legend className="mb-3 flex w-full items-center justify-between">
              <span className="label-mono text-fg-muted">Profile</span>
              <span className="label-mono text-fg-muted">Select one</span>
            </legend>
            <div className="grid gap-3 sm:grid-cols-2">
              {SCAN_PROFILES.map((value) => {
                const id = `${groupId}-${value}`
                const Icon = PROFILE_ICONS[value]
                return (
                  <label
                    key={value}
                    htmlFor={id}
                    className="glass lift flex cursor-pointer flex-col gap-2 rounded-lg border border-glass-edge p-4 hover:border-line-strong has-checked:border-accent has-checked:shadow-neu-inset has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-accent"
                  >
                    <span className="flex items-center gap-2">
                      <input
                        id={id}
                        type="radio"
                        name="profile"
                        value={value}
                        checked={profile === value}
                        onChange={() => setProfile(value)}
                        className="sr-only"
                      />
                      <Icon aria-hidden="true" className="size-4 text-accent" />
                      <span className="text-sm font-semibold text-fg">{PROFILE_LABELS[value]}</span>
                      {value === 'full' && (
                        <span className="ml-auto label-mono text-tertiary">Recommended</span>
                      )}
                    </span>
                    <span className="text-sm text-fg-muted">{PROFILE_HELP[value]}</span>
                  </label>
                )
              })}
            </div>
          </fieldset>

          <div className="glass flex flex-col gap-1.5 rounded-lg border border-glass-edge p-4 has-checked:border-accent/60">
            <label className="flex cursor-pointer items-start gap-3">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => {
                  setAuthorized(e.target.checked)
                  if (e.target.checked) setAuthError(null)
                }}
                aria-invalid={authError ? true : undefined}
                aria-describedby={authError ? `${groupId}-auth-error` : undefined}
                className="mt-0.5 size-5 shrink-0 accent-accent"
              />
              <span className="flex flex-col gap-0.5">
                <span className="text-sm font-medium text-fg">
                  I own this site or have permission to test it.
                </span>
                <span className="text-sm text-fg-muted">
                  AgentGuard runs safe, non-destructive checks only. Required.
                </span>
              </span>
            </label>
            {authError && (
              <p id={`${groupId}-auth-error`} className="pl-8 text-sm text-bad">
                {authError}
              </p>
            )}
          </div>

          <label className="flex cursor-pointer items-start justify-between gap-4">
            <span className="flex flex-col gap-0.5">
              <span className="text-sm font-medium text-fg">Include the containment demo</span>
              <span className="text-sm text-fg-muted">
                Adds a task that tries to reach a forbidden address (169.254.169.254) so you can
                watch it get blocked and the sandbox destroyed.
              </span>
            </span>
            {/* A checkbox styled as a switch: same semantics, larger target. */}
            <input
              type="checkbox"
              checked={containmentDemo}
              onChange={(e) => setContainmentDemo(e.target.checked)}
              className="relative mt-0.5 h-6 w-11 shrink-0 cursor-pointer appearance-none rounded-full bg-line-strong shadow-neu-inset transition-colors before:absolute before:top-0.5 before:left-0.5 before:size-5 before:rounded-full before:bg-switch-knob before:shadow-neu before:transition-transform checked:bg-accent checked:before:translate-x-5"
            />
          </label>

          <div className="flex flex-wrap gap-3 border-t border-line pt-6">
            <Button
              type="submit"
              loading={submitting}
              icon={<Play aria-hidden="true" className="size-4" />}
            >
              {submitting ? 'Starting scan…' : 'Start scan'}
            </Button>
            <Link to="/" className={buttonClasses('ghost')}>
              Cancel
            </Link>
          </div>
        </form>
      </SplitLayout>
    </section>
  )
}
