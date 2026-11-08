import { ApiError } from '../api/client'

/** Short, actionable text for an API failure shown inside a page. */
export function errorText(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'network_error' || error.code === 'timeout') {
      return 'Can’t reach the AgentGuard server. Check your connection and try again.'
    }
    if (error.status === 404) return 'This scan doesn’t exist or belongs to another user.'
    return error.message || `Request failed (${error.code}).`
  }
  return 'Something went wrong. Please try again.'
}
