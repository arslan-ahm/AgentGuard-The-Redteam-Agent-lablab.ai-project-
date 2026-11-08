/**
 * Typed client for the brief 5.8 REST API. Owner: Ayesha (Web app / UI).
 *
 * Request bodies and the Finding / audit shapes come from the frozen `contracts.ts`. Response
 * bodies the brief leaves open (login, scan detail, approvals, report) come from `schemas.ts`,
 * which mirrors the shapes proposed in CR-2.
 */

import type {
  ApiErrorBody,
  ApprovalRequest,
  AuditEvent,
  Finding,
  ScanCreate,
  ScanCreated,
} from './contracts'
import type { ApprovalResult, LoginRequest, Report, ScanDetail, TokenResponse } from './schemas'
import { createSseParser } from './sse'

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

export interface CreateScanOptions {
  /** Sends `X-AgentGuard-Demo: containment` so the scan includes the blocked-request demo task. */
  containmentDemo?: boolean
}

export interface ScanEventHandlers {
  /** An audit event (5.9); `id` is its sequence number for `Last-Event-ID` resume. */
  onAudit?: (event: AuditEvent, id: string | undefined) => void
  /** A fresh scan snapshot. */
  onProgress?: (scan: ScanDetail) => void
}

export interface StreamOptions {
  signal?: AbortSignal
  lastEventId?: string
}

/** Everything the UI needs from the API. Implemented by the real client and the mock client. */
export interface ApiClient {
  login(body: LoginRequest): Promise<TokenResponse>
  listScans(): Promise<ScanDetail[]>
  getScan(scanId: string): Promise<ScanDetail>
  createScan(body: ScanCreate, options?: CreateScanOptions): Promise<ScanCreated>
  listFindings(scanId: string): Promise<Finding[]>
  getAudit(scanId: string): Promise<AuditEvent[]>
  getReport(scanId: string): Promise<Report>
  getReportMarkdown(scanId: string): Promise<string>
  approve(scanId: string, body: ApprovalRequest): Promise<ApprovalResult>
  /** Evidence needs the bearer token, so it is fetched as a Blob (use an object URL in <img>). */
  fetchEvidence(scanId: string, filename: string): Promise<Blob>
  /** Reads the SSE stream until the server closes it (final scan state) or `signal` aborts. */
  streamEvents(scanId: string, handlers: ScanEventHandlers, options?: StreamOptions): Promise<void>
  /** URL of an evidence file (the request still needs the Authorization header). */
  evidenceUrl(scanId: string, filename: string): string
  /** URL of the SSE stream (the request still needs the Authorization header). */
  eventsUrl(scanId: string): string
}

export interface ClientOptions {
  baseUrl?: string
  getToken?: () => string | null
  /** Called on a 401 from any route except login (expired or revoked token). */
  onUnauthorized?: () => void
  fetchImpl?: typeof fetch
  timeoutMs?: number
}

type Method = 'GET' | 'POST'

interface SendOptions {
  body?: unknown
  accept?: string
  headers?: Record<string, string>
  /** `null` disables the timeout (long-lived SSE stream). */
  timeoutMs?: number | null
  signal?: AbortSignal
}

export function createApiClient(options: ClientOptions = {}): ApiClient {
  const baseUrl = options.baseUrl ?? ''
  const fetchImpl = options.fetchImpl ?? fetch
  const defaultTimeoutMs = options.timeoutMs ?? 15_000

  async function send(method: Method, path: string, opts: SendOptions = {}): Promise<Response> {
    const headers: Record<string, string> = {
      Accept: opts.accept ?? 'application/json',
      ...opts.headers,
    }
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
    const token = options.getToken?.()
    if (token) headers.Authorization = `Bearer ${token}`

    const timeoutMs = opts.timeoutMs === undefined ? defaultTimeoutMs : opts.timeoutMs
    const signals = [opts.signal, timeoutMs === null ? undefined : AbortSignal.timeout(timeoutMs)]
    const active = signals.filter((s): s is AbortSignal => s !== undefined)

    let response: Response
    try {
      response = await fetchImpl(`${baseUrl}${API_PREFIX}${path}`, {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: active.length > 1 ? AbortSignal.any(active) : active[0],
      })
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
      const timedOut = cause instanceof DOMException && cause.name === 'TimeoutError'
      throw new ApiError(0, timedOut ? 'timeout' : 'network_error', String(cause))
    }

    if (!response.ok) {
      if (response.status === 401 && path !== '/auth/login') options.onUnauthorized?.()
      const payload: unknown = await response.json().catch(() => null)
      if (isApiErrorBody(payload)) {
        throw new ApiError(response.status, payload.error.code, payload.error.message)
      }
      throw new ApiError(response.status, `http_${response.status}`, response.statusText)
    }
    return response
  }

  async function json<T>(method: Method, path: string, opts?: SendOptions): Promise<T> {
    const response = await send(method, path, opts)
    return (await response.json().catch(() => null)) as T
  }

  const scan = (id: string) => `/scans/${encodeURIComponent(id)}`

  async function streamEvents(
    scanId: string,
    handlers: ScanEventHandlers,
    streamOptions: StreamOptions = {},
  ): Promise<void> {
    const response = await send('GET', `${scan(scanId)}/events`, {
      accept: 'text/event-stream',
      headers: streamOptions.lastEventId ? { 'Last-Event-ID': streamOptions.lastEventId } : {},
      timeoutMs: null,
      signal: streamOptions.signal,
    })
    if (!response.body) return
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
    const parser = createSseParser()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) return
      for (const message of parser.push(value)) {
        let data: unknown
        try {
          data = JSON.parse(message.data)
        } catch {
          continue // malformed message: skip it rather than drop the stream
        }
        if (message.event === 'audit') handlers.onAudit?.(data as AuditEvent, message.id)
        else if (message.event === 'progress') handlers.onProgress?.(data as ScanDetail)
      }
    }
  }

  return {
    login: (body) => json<TokenResponse>('POST', '/auth/login', { body }),
    listScans: () => json<ScanDetail[]>('GET', '/scans'),
    getScan: (scanId) => json<ScanDetail>('GET', scan(scanId)),
    createScan: (body, createOptions = {}) =>
      json<ScanCreated>('POST', '/scans', {
        body,
        headers: createOptions.containmentDemo ? { 'X-AgentGuard-Demo': 'containment' } : {},
      }),
    listFindings: (scanId) => json<Finding[]>('GET', `${scan(scanId)}/findings`),
    getAudit: (scanId) => json<AuditEvent[]>('GET', `${scan(scanId)}/audit`),
    getReport: (scanId) => json<Report>('GET', `${scan(scanId)}/report?format=json`),
    getReportMarkdown: async (scanId) => {
      const response = await send('GET', `${scan(scanId)}/report?format=md`, {
        accept: 'text/markdown',
      })
      return response.text()
    },
    approve: (scanId, body) => json<ApprovalResult>('POST', `${scan(scanId)}/approvals`, { body }),
    fetchEvidence: async (scanId, filename) => {
      const path = `${scan(scanId)}/evidence/${encodeURIComponent(filename)}`
      const response = await send('GET', path, { accept: '*/*' })
      return response.blob()
    },
    streamEvents,
    evidenceUrl: (scanId, filename) =>
      `${baseUrl}${API_PREFIX}${scan(scanId)}/evidence/${encodeURIComponent(filename)}`,
    eventsUrl: (scanId) => `${baseUrl}${API_PREFIX}${scan(scanId)}/events`,
  }
}
