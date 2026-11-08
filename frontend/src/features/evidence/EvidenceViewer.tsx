import { Download, FileJson, ImageOff, Maximize2 } from 'lucide-react'
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react'
import { useApi } from '../../auth/context'
import { Spinner } from '../../components/ui/Spinner'
import { errorText } from '../../lib/errors'
import { evidenceLabel, parseNetworkSummary, type NetworkEntry } from './networkSummary'

const IMAGE = /\.(png|jpe?g|webp|gif)$/i

type Loaded =
  | { kind: 'image'; url: string }
  | { kind: 'network'; entries: NetworkEntry[]; raw: string }
  | { kind: 'text'; raw: string }
  | { kind: 'file'; url: string }

function useEvidence(scanId: string, filename: string) {
  const api = useApi()
  const [state, setState] = useState<{ loaded?: Loaded; error?: unknown }>({})

  useEffect(() => {
    let current = true
    let objectUrl: string | undefined
    api.fetchEvidence(scanId, filename).then(
      async (blob) => {
        let loaded: Loaded
        if (IMAGE.test(filename) || blob.type.startsWith('image/')) {
          objectUrl = URL.createObjectURL(blob)
          loaded = { kind: 'image', url: objectUrl }
        } else if (filename.endsWith('.json') || blob.type.includes('json')) {
          const raw = await blob.text()
          const entries = parseNetworkSummary(raw)
          loaded = entries ? { kind: 'network', entries, raw } : { kind: 'text', raw }
        } else if (blob.type.startsWith('text/')) {
          loaded = { kind: 'text', raw: await blob.text() }
        } else {
          objectUrl = URL.createObjectURL(blob)
          loaded = { kind: 'file', url: objectUrl }
        }
        if (current) setState({ loaded })
        else if (objectUrl) URL.revokeObjectURL(objectUrl)
      },
      (error: unknown) => current && setState({ error }),
    )
    return () => {
      current = false
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [api, scanId, filename])

  return state
}

function statusColor(status: number | null): string {
  if (status === null) return 'text-bad'
  if (status >= 500) return 'text-bad'
  if (status >= 400) return 'text-warn'
  if (status >= 300) return 'text-fg-muted'
  return 'text-success'
}

function NetworkTable({ entries, raw }: { entries: NetworkEntry[]; raw: string }) {
  if (entries.length === 0)
    return <p className="p-4 text-sm text-fg-muted">No requests recorded.</p>
  return (
    <div className="flex flex-col">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Requests captured during the check</caption>
          <thead className="border-b border-line text-xs text-fg-muted">
            <tr>
              <th scope="col" className="px-4 py-2 font-medium">
                Method
              </th>
              <th scope="col" className="px-4 py-2 font-medium">
                Status
              </th>
              <th scope="col" className="px-4 py-2 font-medium">
                URL
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {entries.map((entry, index) => (
              <tr key={`${entry.url}-${index}`} className="align-top">
                <td className="px-4 py-2 font-mono text-xs text-fg">{entry.method}</td>
                <td
                  className={`px-4 py-2 font-mono text-xs tabular-nums ${statusColor(entry.status)}`}
                >
                  {entry.status ?? entry.error ?? 'no response'}
                </td>
                <td className="px-4 py-2 font-mono text-xs break-all text-fg-muted">{entry.url}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <details className="border-t border-line">
        <summary className="cursor-pointer px-4 py-2 text-xs text-fg-muted hover:text-fg">
          Raw JSON (includes recorded response headers)
        </summary>
        <pre className="max-h-64 overflow-auto px-4 pb-3 font-mono text-xs text-fg-muted">
          {raw}
        </pre>
      </details>
    </div>
  )
}

function EvidenceItem({ scanId, filename }: { scanId: string; filename: string }) {
  const { loaded, error } = useEvidence(scanId, filename)
  const label = evidenceLabel(filename)

  let body
  if (error) {
    body = (
      <p className="flex items-center gap-2 p-4 text-sm text-fg-muted">
        <ImageOff aria-hidden="true" className="size-4" />
        {errorText(error)}
      </p>
    )
  } else if (!loaded) {
    body = (
      <p role="status" className="flex items-center gap-2 p-4 text-sm text-fg-muted">
        <Spinner /> Loading evidence…
      </p>
    )
  } else if (loaded.kind === 'image') {
    body = (
      <a
        href={loaded.url}
        target="_blank"
        rel="noreferrer"
        className="group relative block bg-raised"
      >
        <img
          src={loaded.url}
          alt={`Screenshot captured by the check: ${label}`}
          className="max-h-[28rem] w-full object-contain object-top"
        />
        <span className="absolute top-2 right-2 inline-flex items-center gap-1 rounded-sm bg-panel/90 px-2 py-1 text-xs text-fg opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
          <Maximize2 aria-hidden="true" className="size-3.5" />
          Open full size
        </span>
      </a>
    )
  } else if (loaded.kind === 'network') {
    body = <NetworkTable entries={loaded.entries} raw={loaded.raw} />
  } else if (loaded.kind === 'text') {
    body = (
      <pre className="max-h-72 overflow-auto p-4 font-mono text-xs text-fg-muted">{loaded.raw}</pre>
    )
  } else {
    body = (
      <a
        href={loaded.url}
        download={label}
        className="flex items-center gap-2 p-4 text-sm text-accent"
      >
        <Download aria-hidden="true" className="size-4" />
        Download {label}
      </a>
    )
  }

  return (
    <figure className="overflow-hidden glass rounded-lg border border-glass-edge">
      <figcaption className="flex items-center gap-2 border-b border-line bg-raised px-4 py-2 font-mono text-xs text-fg-muted">
        {IMAGE.test(filename) ? null : <FileJson aria-hidden="true" className="size-3.5" />}
        {label}
      </figcaption>
      {body}
    </figure>
  )
}

function tabName(filename: string): string {
  const label = evidenceLabel(filename)
  if (IMAGE.test(filename)) return `Screenshot: ${label.replace(IMAGE, '').replaceAll('_', ' ')}`
  if (/network_summary/.test(label)) return 'Network summary'
  return label
}

/** Evidence files as tabs (screenshots first). A single file is shown without tabs. */
export function EvidenceViewer({ scanId, evidence }: { scanId: string; evidence: string[] }) {
  const baseId = useId()
  const [active, setActive] = useState(0)
  const tabs = useRef<(HTMLButtonElement | null)[]>([])

  if (evidence.length === 0) {
    return <p className="text-sm text-fg-muted">No evidence files were attached to this finding.</p>
  }
  // Screenshots first, then data files.
  const ordered = [...evidence].sort((a, b) => Number(IMAGE.test(b)) - Number(IMAGE.test(a)))
  if (ordered.length === 1) return <EvidenceItem scanId={scanId} filename={ordered[0]} />

  const current = Math.min(active, ordered.length - 1)

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const step = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0
    const jump = event.key === 'Home' ? 0 : event.key === 'End' ? ordered.length - 1 : null
    if (!step && jump === null) return
    event.preventDefault()
    const next = jump ?? (current + step + ordered.length) % ordered.length
    setActive(next)
    tabs.current[next]?.focus()
  }

  return (
    <div className="flex flex-col gap-3">
      <div
        role="tablist"
        aria-label="Evidence files"
        onKeyDown={onKeyDown}
        className="flex flex-wrap gap-1 border-b border-line"
      >
        {ordered.map((filename, index) => {
          const selected = index === current
          return (
            <button
              key={filename}
              ref={(el) => {
                tabs.current[index] = el
              }}
              type="button"
              role="tab"
              id={`${baseId}-tab-${index}`}
              aria-selected={selected}
              aria-controls={`${baseId}-panel-${index}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => setActive(index)}
              className={`-mb-px inline-flex min-h-11 items-center border-b-2 px-3 text-sm transition-colors ${
                selected
                  ? 'border-accent font-medium text-fg'
                  : 'border-transparent text-fg-muted hover:text-fg'
              }`}
            >
              {tabName(filename)}
            </button>
          )
        })}
      </div>
      {ordered.map((filename, index) => (
        <div
          key={filename}
          role="tabpanel"
          id={`${baseId}-panel-${index}`}
          aria-labelledby={`${baseId}-tab-${index}`}
          hidden={index !== current}
        >
          <EvidenceItem scanId={scanId} filename={filename} />
        </div>
      ))}
    </div>
  )
}
