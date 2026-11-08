import { ApiError } from '../api/client'

/** Turns API failures into messages a user can act on. */
export function loginErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return 'Something went wrong. Please try again.'
  switch (error.code) {
    case 'invalid_credentials':
      return 'That email and password don’t match. Check them and try again.'
    case 'rate_limited':
      return 'Too many failed attempts. Wait a few minutes, then try again.'
    case 'network_error':
    case 'timeout':
      return 'Can’t reach the AgentGuard server. Check your connection and try again.'
    case 'auth_not_configured':
      return 'Sign-in isn’t configured on this server yet. Ask the team to set SECRET_KEY.'
    default:
      return error.message || 'Something went wrong. Please try again.'
  }
}
