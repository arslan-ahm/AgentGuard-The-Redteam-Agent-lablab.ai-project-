import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { createApiClient, type ApiClient, type ClientOptions } from '../api/client'
import { createMockClient } from '../api/mock/mockClient'
import { ApiContext, AuthContext, type AuthState } from './context'
import { clearSession, loadSession, saveSession } from './session'

const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === 'true'

interface AuthProviderProps {
  children: ReactNode
  /** Override the API client (tests). Defaults to the mock client in mock mode, else the real one. */
  createClient?: (options: ClientOptions) => ApiClient
  mockMode?: boolean
}

export function AuthProvider({ children, createClient, mockMode = USE_MOCKS }: AuthProviderProps) {
  // `token` only drives re-renders; the API client reads the session store on every request,
  // which also drops an expired token before it is sent.
  const [token, setToken] = useState<string | null>(() => loadSession()?.token ?? null)
  const [sessionExpired, setSessionExpired] = useState(false)

  const expire = useCallback(() => {
    clearSession()
    setToken(null)
    setSessionExpired(true)
  }, [])

  const [client] = useState<ApiClient>(() => {
    const options: ClientOptions = {
      getToken: () => loadSession()?.token ?? null,
      onUnauthorized: expire,
    }
    if (createClient) return createClient(options)
    return mockMode ? createMockClient() : createApiClient(options)
  })

  const login = useCallback(
    async (email: string, password: string) => {
      const response = await client.login({ email, password })
      saveSession({
        token: response.access_token,
        expiresAt: Date.now() + response.expires_in * 1000,
      })
      setToken(response.access_token)
      setSessionExpired(false)
    },
    [client],
  )

  const logout = useCallback(() => {
    clearSession()
    setToken(null)
    setSessionExpired(false)
  }, [])

  const auth = useMemo<AuthState>(
    () => ({ isAuthenticated: token !== null, sessionExpired, mockMode, login, logout }),
    [token, sessionExpired, mockMode, login, logout],
  )

  return (
    <ApiContext.Provider value={client}>
      <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>
    </ApiContext.Provider>
  )
}
