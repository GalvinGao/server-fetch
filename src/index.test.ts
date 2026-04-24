import dns from 'node:dns'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Agent } from 'undici'
import {
  DEFAULT_MAX_RESPONSE_SIZE,
  ResponseExceededMaxSizeError,
  SsrfError,
  createSsrfSafeAgent,
  serverFetch,
  validateUrl,
} from './index'

// Holds a one-shot override for undici fetch; null means use the real fetch.
const mockFetchResponse = { value: null as any }

vi.mock('undici', async (importOriginal) => {
  const actual = await importOriginal<typeof import('undici')>()
  return {
    ...actual,
    fetch: async (...args: Parameters<typeof actual.fetch>) => {
      if (mockFetchResponse.value !== null) {
        const response = mockFetchResponse.value
        mockFetchResponse.value = null
        return response
      }
      return actual.fetch(...args)
    },
  }
})

afterEach(() => {
  mockFetchResponse.value = null
})

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

describe('DEFAULT_MAX_RESPONSE_SIZE', () => {
  it('is 10MB', () => {
    expect(DEFAULT_MAX_RESPONSE_SIZE).toBe(10 * 1024 * 1024)
  })
})

describe('ResponseExceededMaxSizeError', () => {
  it('is re-exported from undici', () => {
    expect(ResponseExceededMaxSizeError).toBeDefined()
    expect(ResponseExceededMaxSizeError.name).toBe('ResponseExceededMaxSizeError')
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

  it('allows public IP literals without DNS lookup', async () => {
    const result = await validateUrl('http://93.184.216.34/')
    expect(result.hostname).toBe('93.184.216.34')
    expect(result.resolvedIps).toEqual(['93.184.216.34'])
  })

  it('rejects with DNS_FAILED when resolution fails', async () => {
    const err = await validateUrl('http://this-domain-does-not-exist-xyz123.example/').catch(
      (e) => e,
    )
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('DNS_FAILED')
  })

  it('rejects with DNS_FAILED when DNS resolves to zero addresses', async () => {
    const spy = vi.spyOn(dns.promises, 'lookup').mockResolvedValueOnce([] as any)
    const err = await validateUrl('http://example.com/').catch((e) => e)
    spy.mockRestore()
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('DNS_FAILED')
    expect(err.message).toContain('zero addresses')
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

  it('accepts a URL object', async () => {
    const res = await serverFetch(new URL('https://example.com'), { timeout: 5000 })
    expect(res.status).toBe(200)
  })

  it('rejects non-standard ports', async () => {
    const err = await serverFetch('http://example.com:8080/').catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('BLOCKED_PORT')
  })

  it('rejects blocked protocols', async () => {
    const err = await serverFetch('ftp://example.com/').catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('BLOCKED_PROTOCOL')
  })

  it('blocks DNS rebinding at connect time (array response)', async () => {
    // Simulate DNS rebinding: validateUrl sees public IP, but the agent's
    // connect.lookup sees a private IP on the second resolution.
    let callCount = 0
    const promisesLookupSpy = vi
      .spyOn(dns.promises, 'lookup')
      .mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as any)
    const lookupSpy = vi.spyOn(dns, 'lookup').mockImplementation(((
      _hostname: any,
      _options: any,
      callback: any,
    ) => {
      callCount++
      // Return private IP — simulates DNS rebinding
      callback(null, [{ address: '127.0.0.1', family: 4 }], 4)
    }) as never)

    const err = await serverFetch('http://rebind-test.example.com/', { timeout: 2000 }).catch(
      (e) => e,
    )
    promisesLookupSpy.mockRestore()
    lookupSpy.mockRestore()

    // undici wraps the SsrfError from connect.lookup in TypeError: fetch failed
    expect(err.cause).toBeInstanceOf(SsrfError)
    expect(err.cause.code).toBe('BLOCKED_IP')
    expect(callCount).toBeGreaterThan(0)
  })

  it('blocks DNS rebinding at connect time (single address response)', async () => {
    const promisesLookupSpy = vi
      .spyOn(dns.promises, 'lookup')
      .mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as any)
    const lookupSpy = vi.spyOn(dns, 'lookup').mockImplementation(((
      _hostname: any,
      _options: any,
      callback: any,
    ) => {
      // Return single string address — non-array path of ssrfSafeLookup
      callback(null, '10.0.0.1', 4)
    }) as never)

    const err = await serverFetch('http://rebind-test.example.com/', { timeout: 2000 }).catch(
      (e) => e,
    )
    promisesLookupSpy.mockRestore()
    lookupSpy.mockRestore()

    expect(err.cause).toBeInstanceOf(SsrfError)
    expect(err.cause.code).toBe('BLOCKED_IP')
  })

  it('allows connection when single address is public', async () => {
    const promisesLookupSpy = vi
      .spyOn(dns.promises, 'lookup')
      .mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as any)
    const lookupSpy = vi.spyOn(dns, 'lookup').mockImplementation(((
      _hostname: any,
      _options: any,
      callback: any,
    ) => {
      // Return single public IP string — non-array path, allowed
      callback(null, '93.184.216.34', 4)
    }) as never)

    // This will attempt a real connection to the mocked IP, which will fail
    // with a network error — but NOT an SsrfError, proving the lookup passed
    const err = await serverFetch('http://mock-public.example.com/', { timeout: 2000 }).catch(
      (e) => e,
    )
    promisesLookupSpy.mockRestore()
    lookupSpy.mockRestore()

    expect(err).not.toBeInstanceOf(SsrfError)
  })

  it('rejects when Content-Length exceeds default maxResponseSize', async () => {
    const hugeContentLength = (DEFAULT_MAX_RESPONSE_SIZE + 1).toString()
    const cancelFn = vi.fn()
    mockFetchResponse.value = {
      headers: new Headers({ 'content-length': hugeContentLength }),
      body: { cancel: cancelFn },
    }

    const err = await serverFetch('https://example.com', { timeout: 2000 }).catch((e) => e)

    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('RESPONSE_TOO_LARGE')
    expect(err.message).toContain(hugeContentLength)
    expect(cancelFn).toHaveBeenCalledOnce()
  })

  it('rejects when Content-Length exceeds custom maxResponseSize', async () => {
    const cancelFn = vi.fn()
    mockFetchResponse.value = {
      headers: new Headers({ 'content-length': '2000' }),
      body: { cancel: cancelFn },
    }

    const err = await serverFetch('https://example.com', {
      timeout: 2000,
      maxResponseSize: 1000,
    }).catch((e) => e)

    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('RESPONSE_TOO_LARGE')
    expect(cancelFn).toHaveBeenCalledOnce()
  })

  it('allows responses with Content-Length at the limit', async () => {
    mockFetchResponse.value = {
      status: 200,
      headers: new Headers({ 'content-length': DEFAULT_MAX_RESPONSE_SIZE.toString() }),
      body: null,
    }

    const res = await serverFetch('https://example.com', { timeout: 2000 })
    expect(res.status).toBe(200)
  })

  it('disables size limit when maxResponseSize is Infinity', async () => {
    mockFetchResponse.value = {
      status: 200,
      headers: new Headers({ 'content-length': '999999999999' }),
      body: null,
    }

    const res = await serverFetch('https://example.com', {
      timeout: 2000,
      maxResponseSize: Infinity,
    })

    expect(res.status).toBe(200)
  })

  it('rejects negative maxResponseSize', async () => {
    const err = await serverFetch('https://example.com', {
      maxResponseSize: -1,
    }).catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('INVALID_OPTION')
  })

  it('rejects zero maxResponseSize', async () => {
    const err = await serverFetch('https://example.com', {
      maxResponseSize: 0,
    }).catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('INVALID_OPTION')
  })

  it('rejects non-integer maxResponseSize', async () => {
    const err = await serverFetch('https://example.com', {
      maxResponseSize: 1.5,
    }).catch((e) => e)
    expect(err).toBeInstanceOf(SsrfError)
    expect(err.code).toBe('INVALID_OPTION')
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
