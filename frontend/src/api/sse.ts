/**
 * Minimal Server-Sent Events parser for `GET /scans/{id}/events`.
 *
 * The stream needs the bearer token in a header, which a browser `EventSource` cannot send
 * (CR-2), so the client reads it with `fetch` and feeds the text through this parser.
 */

export interface SseMessage {
  /** `event:` field; `message` when absent. */
  event: string
  data: string
  /** `id:` field, used for `Last-Event-ID` resume. */
  id?: string
}

/** Incremental parser: push text chunks in, get complete messages out. */
export function createSseParser() {
  let buffer = ''

  function parseBlock(block: string): SseMessage | null {
    let event = 'message'
    let id: string | undefined
    const data: string[] = []
    for (const line of block.split('\n')) {
      if (line === '' || line.startsWith(':')) continue // blank or comment (keep-alive)
      const colon = line.indexOf(':')
      const field = colon === -1 ? line : line.slice(0, colon)
      let value = colon === -1 ? '' : line.slice(colon + 1)
      if (value.startsWith(' ')) value = value.slice(1)
      if (field === 'event') event = value
      else if (field === 'data') data.push(value)
      else if (field === 'id') id = value
    }
    if (data.length === 0) return null
    return { event, data: data.join('\n'), id }
  }

  return {
    push(chunk: string): SseMessage[] {
      buffer += chunk.replace(/\r\n?/g, '\n')
      const messages: SseMessage[] = []
      let boundary = buffer.indexOf('\n\n')
      while (boundary !== -1) {
        const message = parseBlock(buffer.slice(0, boundary))
        if (message) messages.push(message)
        buffer = buffer.slice(boundary + 2)
        boundary = buffer.indexOf('\n\n')
      }
      return messages
    },
  }
}
