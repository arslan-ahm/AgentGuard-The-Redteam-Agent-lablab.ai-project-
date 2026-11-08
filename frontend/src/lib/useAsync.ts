import { useCallback, useEffect, useState } from 'react'

export interface AsyncState<T> {
  data: T | undefined
  error: unknown
  loading: boolean
  /** Re-runs the loader (e.g. a "Try again" button). */
  reload: () => void
}

/**
 * Runs `load` when `key` changes and tracks loading/error state. Results from a superseded run
 * (key changed or component unmounted) are ignored, so a slow response never overwrites a newer one.
 */
export function useAsync<T>(load: () => Promise<T>, key: string): AsyncState<T> {
  const [state, setState] = useState<{ data?: T; error: unknown; loading: boolean }>({
    error: null,
    loading: true,
  })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let current = true
    setState((prev) => ({ data: prev.data, error: null, loading: true }))
    load().then(
      (data) => current && setState({ data, error: null, loading: false }),
      (error: unknown) => current && setState({ error, loading: false }),
    )
    return () => {
      current = false
    }
    // `load` is recreated every render; `key` + `attempt` decide when to re-run.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, attempt])

  const reload = useCallback(() => setAttempt((n) => n + 1), [])
  return { data: state.data, error: state.error, loading: state.loading, reload }
}
