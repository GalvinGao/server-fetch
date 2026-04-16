import { describe, expect, it } from 'vitest'
import { Agent } from 'undici'
import { SsrfError, createSsrfSafeAgent, serverFetch, validateUrl } from './index'

describe('SsrfError', () => {
  it('has code, url, and message', () => {
    const err = new SsrfError('BLOCKED_IP', 'Blocked IP: 127.0.0.1', 'http://localhost/')
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('SsrfError')
    expect(err.code).toBe('BLOCKED_IP')
    expect(err.url).toBe('http://localhost/')
    expect(err.message).toBe('Blocked IP: 127.0.0.1')
  })
})

describe('validateUrl', () => {
  it('allows public HTTPS URLs', async () => {
    const result = await validateUrl('https://example.com')
    expect(result.hostname).toBe('example.com')
    expect(result.parsed.protocol).toBe('https:')
    expect(result.resolvedIps.length).toBeGreaterThan(0)
  })

  it('allows public HTTP URLs', async () => {
    const result = await validateUrl('http://example.com')
    expect(result.parsed.protocol).toBe('http:')
  })

  it('rejects non-http protocols', async () => {
    await expect(validateUrl('ftp://example.com/')).rejects.toThrow(SsrfError)
    await expect(validateUrl('file:///etc/passwd')).rejects.toThrow(SsrfError)
    await expect(validateUrl('gopher://internal/')).rejects.toThrow(SsrfError)
  })

  it('rejects non-http with BLOCKED_PROTOCOL code', async () => {
    const err = await validateUrl('ftp://example.com/').catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('BLOCKED_PROTOCOL')
  })

  it('rejects non-standard ports', async () => {
    await expect(validateUrl('http://example.com:8080/')).rejects.toThrow(SsrfError)
    await expect(validateUrl('https://example.com:4443/')).rejects.toThrow(SsrfError)
  })

  it('rejects non-standard ports with BLOCKED_PORT code', async () => {
    const err = await validateUrl('http://example.com:8080/').catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('BLOCKED_PORT')
  })

  it('rejects invalid URLs', async () => {
    await expect(validateUrl('not-a-url')).rejects.toThrow(SsrfError)
    await expect(validateUrl('')).rejects.toThrow(SsrfError)
  })

  it('rejects invalid URLs with INVALID_URL code', async () => {
    const err = await validateUrl('not-a-url').catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('INVALID_URL')
  })

  it('rejects private IPv4 literals', async () => {
    await expect(validateUrl('http://127.0.0.1/')).rejects.toThrow(SsrfError)
    await expect(validateUrl('http://10.0.0.1/')).rejects.toThrow(SsrfError)
    await expect(validateUrl('http://192.168.1.1/')).rejects.toThrow(SsrfError)
  })

  it('rejects cloud metadata IP', async () => {
    await expect(validateUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(SsrfError)
  })

  it('rejects IPv6 loopback', async () => {
    await expect(validateUrl('http://[::1]/')).rejects.toThrow(SsrfError)
  })

  it('rejects hostnames that resolve to private IPs', async () => {
    await expect(validateUrl('http://localhost/')).rejects.toThrow(SsrfError)
  })

  it('rejects private IPs with BLOCKED_IP code', async () => {
    const err = await validateUrl('http://127.0.0.1/').catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('BLOCKED_IP')
  })
})

describe('serverFetch', () => {
  it('blocks private IPs at the dispatcher level', async () => {
    await expect(serverFetch('http://127.0.0.1/', { timeout: 2000 })).rejects.toThrow(SsrfError)
  })

  it('blocks localhost via DNS at the dispatcher level', async () => {
    await expect(serverFetch('http://localhost/', { timeout: 2000 })).rejects.toThrow(SsrfError)
  })

  it('fetches public URLs successfully', async () => {
    const res = await serverFetch('https://example.com', { timeout: 5000 })
    expect(res.status).toBe(200)
  })
})

describe('createSsrfSafeAgent', () => {
  it('returns an Agent instance', () => {
    const agent = createSsrfSafeAgent()
    expect(agent).toBeInstanceOf(Agent)
  })

  it('merges custom options while keeping safe lookup', () => {
    const agent = createSsrfSafeAgent({ connections: 5 })
    expect(agent).toBeInstanceOf(Agent)
  })
})
