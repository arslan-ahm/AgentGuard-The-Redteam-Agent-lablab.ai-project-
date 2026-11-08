import { describe, expect, it } from 'vitest'
import { ApiError, createApiClient } from './client'

type Call = { url: string; init: RequestInit }

function fakeFetch(status: number, body: unknown, calls: Call[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} })
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch
}

describe('createApiClient', () => {
  it('posts a scan with JSON body and bearer token', async () => {
    const calls: Call[] = []
    const client = createApiClient({
      fetchImpl: fakeFetch(202, { id: 'abc', status: 'queued' }, calls),
      getToken: () => 'tok',
    })
    const created = await client.createScan({
      target_url: 'https://x.test',
      profile: 'full',
      authorized: true,
    })

    expect(created).toEqual({ id: 'abc', status: 'queued' })
    expect(calls[0].url).toBe('/api/v1/scans')
    expect(calls[0].init.method).toBe('POST')
    expect(JSON.parse(String(calls[0].init.body))).toEqual({
      target_url: 'https://x.test',
      profile: 'full',
      authorized: true,
    })
    const headers = calls[0].init.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer tok')
  })

  it('omits Authorization when there is no token', async () => {
    const calls: Call[] = []
    await createApiClient({ fetchImpl: fakeFetch(200, [], calls) }).listFindings('s1')
    const headers = calls[0].init.headers as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
    expect(calls[0].init.body).toBeUndefined()
  })

  it('maps the 5.8 error shape to ApiError', async () => {
    const client = createApiClient({
      fetchImpl: fakeFetch(501, { error: { code: 'not_implemented', message: 'later' } }),
    })
    const error = await client.listFindings('s1').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 501, code: 'not_implemented', message: 'later' })
  })

  it('falls back to http_<status> when the body is not the error shape', async () => {
    const client = createApiClient({ fetchImpl: fakeFetch(502, { detail: 'bad gateway' }) })
    await expect(client.getAudit('s1')).rejects.toMatchObject({ status: 502, code: 'http_502' })
  })

  it('reports network failures as network_error', async () => {
    const failing = (async () => {
      throw new TypeError('Failed to fetch')
    }) as typeof fetch
    const client = createApiClient({ fetchImpl: failing })
    await expect(client.getAudit('s1')).rejects.toMatchObject({ status: 0, code: 'network_error' })
  })

  it('sends the containment demo header only when asked', async () => {
    const calls: Call[] = []
    const client = createApiClient({
      fetchImpl: fakeFetch(202, { id: 'a', status: 'queued' }, calls),
    })
    await client.createScan({ target_url: 'https://x.test', profile: 'smoke', authorized: true })
    await client.createScan(
      { target_url: 'https://x.test', profile: 'full', authorized: true },
      { containmentDemo: true },
    )
    const first = calls[0].init.headers as Record<string, string>
    const second = calls[1].init.headers as Record<string, string>
    expect(first['X-AgentGuard-Demo']).toBeUndefined()
    expect(second['X-AgentGuard-Demo']).toBe('containment')
  })

  it('calls onUnauthorized on a 401, except for login', async () => {
    let expired = 0
    const body = { error: { code: 'unauthorized', message: 'missing or invalid bearer token' } }
    const client = createApiClient({
      fetchImpl: fakeFetch(401, body),
      onUnauthorized: () => {
        expired += 1
      },
    })
    await expect(client.listScans()).rejects.toMatchObject({ status: 401 })
    await expect(client.login({ email: 'a@b.c', password: 'x' })).rejects.toMatchObject({
      status: 401,
    })
    expect(expired).toBe(1)
  })

  it('requests the JSON report and the Markdown report', async () => {
    const calls: Call[] = []
    const client = createApiClient({ fetchImpl: fakeFetch(200, 'body', calls) })
    await client.getReport('s1')
    await client.getReportMarkdown('s1')
    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/scans/s1/report?format=json',
      '/api/v1/scans/s1/report?format=md',
    ])
    expect((calls[1].init.headers as Record<string, string>).Accept).toBe('text/markdown')
  })

  it('streams audit and progress events and resumes with Last-Event-ID', async () => {
    const calls: Call[] = []
    const sse =
      'id: 7\nevent: audit\ndata: {"action":"sandbox_destroyed","decision":"blocked"}\n\n' +
      ': keep-alive\n\n' +
      'event: progress\ndata: {"id":"s1","status":"running"}\n\n'
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      return new Response(sse, { status: 200, headers: { 'Content-Type': 'text/event-stream' } })
    }) as typeof fetch

    const audit: Array<[string, string | undefined]> = []
    const progress: string[] = []
    await createApiClient({ fetchImpl, getToken: () => 'tok' }).streamEvents(
      's1',
      {
        onAudit: (event, id) => audit.push([event.action, id]),
        onProgress: (scan) => progress.push(scan.status),
      },
      { lastEventId: '6' },
    )

    expect(audit).toEqual([['sandbox_destroyed', '7']])
    expect(progress).toEqual(['running'])
    const headers = calls[0].init.headers as Record<string, string>
    expect(headers['Last-Event-ID']).toBe('6')
    expect(headers.Authorization).toBe('Bearer tok')
    expect(headers.Accept).toBe('text/event-stream')
  })

  it('encodes ids and filenames in URLs', () => {
    const client = createApiClient({ baseUrl: 'https://ag.test' })
    expect(client.evidenceUrl('a/b', '../secret.png')).toBe(
      'https://ag.test/api/v1/scans/a%2Fb/evidence/..%2Fsecret.png',
    )
    expect(client.eventsUrl('s1')).toBe('https://ag.test/api/v1/scans/s1/events')
  })
})
