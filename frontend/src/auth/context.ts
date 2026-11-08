import { createContext, useContext } from 'react'
import type { ApiClient } from '../api/client'

export interface AuthState {
  isAuthenticated: boolean
  /** True after the API rejected the stored token (shown once on the login page). */
  sessionExpired: boolean
  /** True when the UI runs against the in-memory mock API. */
  mockMode: boolean
  login(email: string, password: string): Promise<void>
  logout(): void
}

export const AuthContext = createContext<AuthState | null>(null)
export const ApiContext = createContext<ApiClient | null>(null)

export function useAuth(): AuthState {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>')
  return value
}

export function useApi(): ApiClient {
  const value = useContext(ApiContext)
  if (!value) throw new Error('useApi must be used inside <AuthProvider>')
  return value
}
