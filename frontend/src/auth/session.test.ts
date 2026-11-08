import { afterEach, describe, expect, it, vi } from 'vitest'
import { clearSession, loadSession, saveSession } from './session'

describe('session store', () => {
  afterEach(() => vi.restoreAllMocks())

  it('round-trips a session and clears it', () => {
    saveSession({ token: 'abc', expiresAt: 2_000 })
    expect(loadSession(1_000)).toEqual({ token: 'abc', expiresAt: 2_000 })
    clearSession()
    expect(loadSession(1_000)).toBeNull()
  })

  it('drops an expired session from storage', () => {
    saveSession({ token: 'abc', expiresAt: 2_000 })
    expect(loadSession(2_000)).toBeNull()
    expect(window.sessionStorage.getItem('agentguard.session')).toBeNull()
  })

  it('ignores malformed stored values', () => {
    window.sessionStorage.setItem('agentguard.session', '{"token":1}')
    expect(loadSession()).toBeNull()
    window.sessionStorage.setItem('agentguard.session', 'not json')
    expect(loadSession()).toBeNull()
  })

  it('keeps the session in memory when storage throws', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
    saveSession({ token: 'mem', expiresAt: 2_000 })
    expect(loadSession(1_000)?.token).toBe('mem')
  })
})
