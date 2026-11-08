/** Saves text as a file through a temporary object URL. */
export function downloadText(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.append(link)
  link.click()
  link.remove()
  // Give the browser a moment to start the download before releasing the URL.
  setTimeout(() => URL.revokeObjectURL(url), 1_000)
}

/** `agentguard-<host>-<yyyy-mm-dd>` for export file names. */
export function reportBaseName(targetUrl: string, createdAt: string): string {
  let host = 'scan'
  try {
    host = new URL(targetUrl).hostname
  } catch {
    // keep the fallback
  }
  const safeHost = host.replace(/[^a-z0-9.-]/gi, '-')
  return `agentguard-${safeHost}-${createdAt.slice(0, 10)}`
}
