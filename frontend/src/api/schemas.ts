/**
 * Response shapes the brief (5.8) leaves open, mirrored from `backend/app/api/schemas.py`.
 *
 * Proposed in `docs/change-requests/CR-2-api-response-shapes.md` and not yet approved, so they
 * live here and not in the frozen `contracts.ts`. Move them there once CR-2 is approved.
 */

import type { ApprovalAction, Finding, ScanProfile, ScanStatus } from './contracts'

/** Body of `POST /auth/login`. */
export interface LoginRequest {
  email: string
  password: string
}

/** Response of `POST /auth/login`. `expires_in` is in seconds. */
export interface TokenResponse {
  access_token: string
  token_type: 'bearer'
  expires_in: number
}

export interface Progress {
  tasks_total: number
  tasks_done: number
}

/** Rows of `GET /scans` and the body of `GET /scans/{id}`; also the SSE `progress` event. */
export interface ScanDetail {
  id: string
  target_url: string
  profile: ScanProfile
  status: ScanStatus
  progress: Progress
  score?: number | null
  recommendation?: string | null
  summary?: string | null
  error?: string | null
  /** ISO 8601 timestamps. */
  created_at: string
  updated_at: string
}

/** Response of `POST /scans/{id}/approvals`. `executed` is always false (decision only). */
export interface ApprovalResult {
  scan_id: string
  action: ApprovalAction
  approved: boolean
  scan_status: ScanStatus
  executed: boolean
}

/** Response of `GET /scans/{id}/report?format=json`. */
export interface Report {
  scan: ScanDetail
  findings: Finding[]
  /** Findings below 0.5 confidence (brief 6.7), excluded from the score. */
  needs_review: Finding[]
}
