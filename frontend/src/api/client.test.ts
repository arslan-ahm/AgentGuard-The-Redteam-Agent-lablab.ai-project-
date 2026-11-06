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
    const created = await client.createScan({ target_url: 'https://x.test', profile: 'full' })

    expect(created).toEqual({ id: 'abc', status: 'queued' })
    expect(calls[0].url).toBe('/api/v1/scans')
    expect(calls[0].init.method).toBe('POST')
    expect(JSON.parse(String(calls[0].init.body))).toEqual({
      target_url: 'https://x.test',
      profile: 'full',
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

  it('encodes ids and filenames in URLs', () => {
    const client = createApiClient({ baseUrl: 'https://ag.test' })
    expect(client.evidenceUrl('a/b', '../secret.png')).toBe(
      'https://ag.test/api/v1/scans/a%2Fb/evidence/..%2Fsecret.png',
    )
    expect(client.eventsUrl('s1')).toBe('https://ag.test/api/v1/scans/s1/events')
  })
})
