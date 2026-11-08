/**
 * Bearer-token storage. Uses sessionStorage (cleared when the tab closes) rather than
 * localStorage to limit how long a token survives on a shared machine. Storage can be
 * unavailable (private mode, blocked site data), so every access is guarded.
 */

const KEY = 'agentguard.session'

/** In-memory copy, so a session still works for this page load when storage is blocked. */
let memory: StoredSession | null = null

export interface StoredSession {
  token: string
  /** Epoch milliseconds. */
  expiresAt: number
}

function storage(): Storage | null {
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

export function loadSession(now: number = Date.now()): StoredSession | null {
  let session = memory
  try {
    const raw = storage()?.getItem(KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<StoredSession>
      if (typeof parsed.token === 'string' && typeof parsed.expiresAt === 'number') {
        session = { token: parsed.token, expiresAt: parsed.expiresAt }
      }
    }
  } catch {
    // Unreadable storage: fall back to the in-memory copy.
  }
  if (session && session.expiresAt <= now) {
    clearSession()
    return null
  }
  return session
}

export function saveSession(session: StoredSession): void {
  memory = session
  try {
    storage()?.setItem(KEY, JSON.stringify(session))
  } catch {
    // Storage blocked: the in-memory copy keeps the session for this page load.
  }
}

export function clearSession(): void {
  memory = null
  try {
    storage()?.removeItem(KEY)
  } catch {
    // Nothing to clear.
  }
}
