/**
 * `network_summary.json` written by the sandbox runner: a list of
 * `{url, method?, status, headers?, error?}` entries (see `sandbox-worker/checks/security/_common.py`).
 * Parsed defensively because evidence is untrusted output.
 */

export interface NetworkEntry {
  url: string
  method: string
  status: number | null
  error?: string
}

export function parseNetworkSummary(raw: string): NetworkEntry[] | null {
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return null
  }
  if (!Array.isArray(data)) return null
  const entries: NetworkEntry[] = []
  for (const item of data) {
    if (typeof item !== 'object' || item === null) return null
    const { url, method, status, error } = item as Record<string, unknown>
    if (typeof url !== 'string') return null
    entries.push({
      url,
      method: typeof method === 'string' ? method.toUpperCase() : 'GET',
      status: typeof status === 'number' ? status : null,
      error: typeof error === 'string' ? error : undefined,
    })
  }
  return entries
}

/** Display name without the `<task_id>__` prefix the API adds (CR-2). */
export function evidenceLabel(filename: string): string {
  const cut = filename.indexOf('__')
  return cut === -1 ? filename : filename.slice(cut + 2)
}
