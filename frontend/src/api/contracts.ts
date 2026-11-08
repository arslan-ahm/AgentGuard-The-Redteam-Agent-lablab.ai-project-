/**
 * Frozen AgentGuard contracts (PROJECT_BRIEF.md section 5), TypeScript mirror of
 * `shared/contracts-py/src/agentguard_contracts/__init__.py`. Change both together, and
 * only through an approved change request (brief section 8).
 */

export const SCAN_PROFILES = ['smoke', 'qa', 'security', 'full'] as const
export type ScanProfile = (typeof SCAN_PROFILES)[number]

export const SCAN_STATUSES = [
  'queued',
  'planning',
  'running',
  'verifying',
  'awaiting_approval',
  'completed',
  'failed',
  'blocked',
] as const
export type ScanStatus = (typeof SCAN_STATUSES)[number]

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const
export type Severity = (typeof SEVERITIES)[number]

export type FindingCategory = 'qa' | 'security' | 'accessibility'

/** 5.4 Finding. */
export interface Finding {
  id: string
  scan_id: string
  title: string
  category: FindingCategory
  severity: Severity
  /** 0..1 */
  confidence: number
  url: string
  /** Filenames, resolved through `GET /scans/{id}/evidence/{filename}`. */
  evidence: string[]
  reproduction: string[]
  impact: string
  recommended_fix: string
  /** `category.name`, e.g. `security.error_leak`. */
  check_id: string
  verified: boolean
}

/** Body of `POST /scans`. */
export interface ScanCreate {
  target_url: string
  profile: ScanProfile
  /** CR-4: the user attests they own the site or may test it. Recorded in the audit log. */
  authorized: true
  credentials_ref?: string | null
}

/** Response of `POST /scans`. */
export interface ScanCreated {
  id: string
  status: ScanStatus
}

export type ApprovalAction = 'github_issue' | 'send_report'

/** Body of `POST /scans/{id}/approvals`. */
export interface ApprovalRequest {
  action: ApprovalAction
  approved: boolean
}

export type ReportFormat = 'json' | 'md' | 'pdf'

/** 5.9 audit event. */
export interface AuditEvent {
  ts: string
  scan_id: string
  task_id?: string | null
  actor: 'api' | 'agent' | 'sandbox' | 'policy'
  action: string
  target: string
  decision: 'allowed' | 'blocked'
  reason: string
}

/** 5.8 error shape. */
export interface ApiErrorBody {
  error: { code: string; message: string }
}

/** 5.10 recommendation text. */
export const RECOMMENDATIONS = {
  block: 'Block release',
  fixFirst: 'Fix high-priority issues before release',
  safe: 'Safe to ship with monitoring',
} as const
