import { useEffect, useState } from 'react'
import type { ApiClient } from '../api/client'
import { ApiError } from '../api/client'
import type { AuditEvent } from '../api/contracts'
import type { ScanDetail } from '../api/schemas'
import { FINAL_STATUSES } from './format'

export type Connection = 'connecting' | 'live' | 'reconnecting' | 'closed' | 'error'

export interface ScanEventsState {
  scan: ScanDetail | undefined
  events: AuditEvent[]
  connection: Connection
  error: unknown
}

const MAX_RETRIES = 5

/**
 * Follows `GET /scans/{id}/events`: replays the audit trail, then streams new events and
 * progress until the scan reaches a final state. Drops are retried with backoff, resuming
 * from the last event id so nothing is shown twice. Mount one instance per scan (use a `key`).
 */
export function useScanEvents(api: ApiClient, scanId: string): ScanEventsState {
  const [state, setState] = useState<ScanEventsState>({
    scan: undefined,
    events: [],
    connection: 'connecting',
    error: null,
  })

  useEffect(() => {
    const controller = new AbortController()
    let lastId: string | undefined
    let latest: ScanDetail | undefined

    async function follow() {
      // The stream has no initial snapshot for an idle scan, so fetch one first.
      try {
        latest = await api.getScan(scanId)
        setState((s) => ({ ...s, scan: latest }))
      } catch (error) {
        if (!controller.signal.aborted) setState((s) => ({ ...s, connection: 'error', error }))
        return
      }

      for (let attempt = 0; !controller.signal.aborted; attempt += 1) {
        try {
          setState((s) => ({ ...s, connection: attempt === 0 ? 'connecting' : 'reconnecting' }))
          await api.streamEvents(
            scanId,
            {
              onAudit: (event, id) => {
                if (id !== undefined) lastId = id
                attempt = 0
                setState((s) => ({ ...s, connection: 'live', events: [...s.events, event] }))
              },
              onProgress: (scan) => {
                latest = scan
                attempt = 0
                setState((s) => ({ ...s, connection: 'live', scan }))
              },
            },
            { signal: controller.signal, lastEventId: lastId },
          )
          if (latest && FINAL_STATUSES.has(latest.status)) {
            setState((s) => ({ ...s, connection: 'closed' }))
            return
          }
          // Server closed early (e.g. its max stream time): reconnect and resume.
        } catch (error) {
          if (controller.signal.aborted) return
          const fatal = error instanceof ApiError && error.status >= 400 && error.status < 500
          if (fatal || attempt >= MAX_RETRIES) {
            setState((s) => ({ ...s, connection: 'error', error }))
            return
          }
        }
        await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * 2 ** attempt, 10_000)))
      }
    }

    void follow()
    return () => controller.abort()
  }, [api, scanId])

  return state
}
