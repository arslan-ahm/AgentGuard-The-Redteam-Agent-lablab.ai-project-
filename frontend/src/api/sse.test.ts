import { describe, expect, it } from 'vitest'
import { createSseParser } from './sse'

describe('createSseParser', () => {
  it('parses the backend message format with id, event and data', () => {
    const parser = createSseParser()
    const messages = parser.push('id: 4\nevent: audit\ndata: {"action":"scan.status"}\n\n')
    expect(messages).toEqual([{ id: '4', event: 'audit', data: '{"action":"scan.status"}' }])
  })

  it('buffers messages split across chunks', () => {
    const parser = createSseParser()
    expect(parser.push('event: progress\nda')).toEqual([])
    expect(parser.push('ta: {"a":1}\n')).toEqual([])
    expect(parser.push('\n')).toEqual([{ event: 'progress', data: '{"a":1}', id: undefined }])
  })

  it('ignores keep-alive comments and handles CRLF and multi-line data', () => {
    const parser = createSseParser()
    const messages = parser.push(': keep-alive\r\n\r\ndata: line1\r\ndata: line2\r\n\r\n')
    expect(messages).toEqual([{ event: 'message', data: 'line1\nline2', id: undefined }])
  })

  it('returns several messages from one chunk', () => {
    const parser = createSseParser()
    const messages = parser.push('event: a\ndata: 1\n\nevent: b\ndata: 2\n\n')
    expect(messages.map((m) => m.event)).toEqual(['a', 'b'])
  })
})
