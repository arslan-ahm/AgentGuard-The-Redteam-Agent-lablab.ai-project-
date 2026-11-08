import { X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { ApiError } from '../../api/client'
import type { ApprovalAction, Finding } from '../../api/contracts'
import type { ApprovalResult, ScanDetail } from '../../api/schemas'
import { useApi } from '../../auth/context'
import { Alert } from '../../components/ui/Alert'
import { Button } from '../../components/ui/Button'
import { githubIssueBody, githubIssueTitle } from '../report/githubIssue'

const ACTION_TEXT: Record<ApprovalAction, { title: string; intro: string }> = {
  github_issue: {
    title: 'Create a GitHub issue',
    intro: 'Review the issue AgentGuard would file with these findings.',
  },
  send_report: {
    title: 'Send the report',
    intro: 'Review what the report contains before it is shared.',
  },
}

interface ApprovalDialogProps {
  action: ApprovalAction | null
  scan: ScanDetail
  findings: Finding[]
  onClose: () => void
  onDecided: (result: ApprovalResult) => void
}

/** Human approval step (brief 3.6): nothing leaves AgentGuard without an explicit decision. */
export function ApprovalDialog({
  action,
  scan,
  findings,
  onClose,
  onDecided,
}: ApprovalDialogProps) {
  const api = useApi()
  const dialog = useRef<HTMLDialogElement>(null)
  const [pending, setPending] = useState<boolean | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ApprovalResult | null>(null)

  useEffect(() => {
    const el = dialog.current
    if (!el) return
    if (action && !el.open) {
      setError(null)
      setResult(null)
      el.showModal()
    } else if (!action && el.open) {
      el.close()
    }
  }, [action])

  async function decide(approved: boolean) {
    if (!action) return
    setPending(approved)
    setError(null)
    try {
      const response = await api.approve(scan.id, { action, approved })
      setResult(response)
      onDecided(response)
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.code === 'already_decided'
          ? 'This action was already decided. Each decision can be made once.'
          : caught instanceof ApiError
            ? caught.message
            : 'Something went wrong. Please try again.',
      )
    } finally {
      setPending(null)
    }
  }

  const text = action ? ACTION_TEXT[action] : null
  const counts = findings.length

  return (
    <dialog
      ref={dialog}
      onClose={onClose}
      aria-labelledby="approval-title"
      className="m-auto w-[min(42rem,calc(100vw-2rem))] glass rounded-lg [--glass-alpha:92%] border border-glass-edge p-0 text-fg backdrop:bg-black/40 backdrop:backdrop-blur-sm"
    >
      {text && action && (
        <div className="flex max-h-[85dvh] flex-col">
          <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
            <div>
              <h2 id="approval-title" className="text-lg font-semibold">
                {text.title}
              </h2>
              <p className="mt-1 text-sm text-fg-muted">{text.intro}</p>
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="inline-flex size-11 shrink-0 items-center justify-center neu-soft rounded-md text-fg-muted hover:bg-raised hover:text-accent"
            >
              <X aria-hidden="true" className="size-4" />
            </button>
          </div>

          <div className="flex flex-col gap-4 overflow-y-auto px-5 py-4">
            {action === 'github_issue' ? (
              <div className="flex flex-col gap-2">
                <p className="text-sm font-medium">{githubIssueTitle(scan)}</p>
                <pre className="max-h-72 overflow-auto rounded-md border border-line bg-raised p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap text-fg-muted">
                  {githubIssueBody(scan, findings)}
                </pre>
              </div>
            ) : (
              <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted">
                <li>Release score {scan.score ?? 'n/a'}/100 and the recommendation</li>
                <li>
                  {counts} verified {counts === 1 ? 'finding' : 'findings'} with reproduction steps
                  and suggested fixes
                </li>
                <li>Evidence references (screenshots and network summaries)</li>
              </ul>
            )}

            {error && <Alert tone="error" title={error} />}
            {result && (
              <Alert
                tone={result.approved ? 'success' : 'info'}
                title={result.approved ? 'Approved and recorded' : 'Rejected and recorded'}
              >
                The decision is in the audit log.
                {result.approved &&
                  !result.executed &&
                  ' Nothing has been sent yet: delivery is a separate step that is not connected in this version.'}
              </Alert>
            )}
          </div>

          <div className="flex flex-wrap justify-end gap-2 border-t border-line px-5 py-4">
            {result ? (
              <Button variant="secondary" onClick={onClose}>
                Done
              </Button>
            ) : (
              <>
                <Button
                  variant="secondary"
                  onClick={() => decide(false)}
                  loading={pending === false}
                  disabled={pending !== null}
                >
                  Reject
                </Button>
                <Button
                  onClick={() => decide(true)}
                  loading={pending === true}
                  disabled={pending !== null}
                >
                  Approve
                </Button>
              </>
            )}
          </div>
        </div>
      )}
    </dialog>
  )
}
