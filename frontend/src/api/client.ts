/**
 * Typed client for the brief 5.8 REST API. Owner: Ayesha (Web app / UI).
 *
 * Only endpoints whose response shape is fixed by the brief are typed here. Responses the
 * brief leaves open (login token, scan detail, scan list) get typed once Sohaib's API
 * defines them through a change request.
 */

import type {
  ApiErrorBody,
  ApprovalRequest,
  AuditEvent,
  Finding,
  ScanCreate,
  ScanCreated,
} from './contracts'

export const API_PREFIX = '/api/v1'

/** Thrown for any non-2xx response; carries the 5.8 error code. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false
  const error = (value as { error: unknown }).error
  return (
    typeof error === 'object' &&
    error !== null &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { message?: unknown }).message === 'string'
  )
}

export interface ClientOptions {
  baseUrl?: string
  getToken?: () => string | null
  fetchImpl?: typeof fetch
  timeoutMs?: number
}

export function createApiClient(options: ClientOptions = {}) {
  const baseUrl = options.baseUrl ?? ''
  const fetchImpl = options.fetchImpl ?? fetch
  const timeoutMs = options.timeoutMs ?? 15_000

  async function request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const token = options.getToken?.()
    if (token) headers.Authorization = `Bearer ${token}`

    let response: Response
    try {
      response = await fetchImpl(`${baseUrl}${API_PREFIX}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      })
    } catch (cause) {
      const timedOut = cause instanceof DOMException && cause.name === 'TimeoutError'
      throw new ApiError(0, timedOut ? 'timeout' : 'network_error', String(cause))
    }

    const payload: unknown = await response.json().catch(() => null)
    if (!response.ok) {
      if (isApiErrorBody(payload)) {
        throw new ApiError(response.status, payload.error.code, payload.error.message)
      }
      throw new ApiError(response.status, `http_${response.status}`, response.statusText)
    }
    return payload as T
  }

  const scan = (id: string) => `/scans/${encodeURIComponent(id)}`

  return {
    createScan: (body: ScanCreate) => request<ScanCreated>('POST', '/scans', body),
    listFindings: (scanId: string) => request<Finding[]>('GET', `${scan(scanId)}/findings`),
    getAudit: (scanId: string) => request<AuditEvent[]>('GET', `${scan(scanId)}/audit`),
    approve: (scanId: string, body: ApprovalRequest) =>
      request<unknown>('POST', `${scan(scanId)}/approvals`, body),
    /** URL for an evidence file (use in <img src>). */
    evidenceUrl: (scanId: string, filename: string) =>
      `${baseUrl}${API_PREFIX}${scan(scanId)}/evidence/${encodeURIComponent(filename)}`,
    /** URL for the SSE progress stream (use with EventSource). */
    eventsUrl: (scanId: string) => `${baseUrl}${API_PREFIX}${scan(scanId)}/events`,
  }
}

export type ApiClient = ReturnType<typeof createApiClient>
