import dns from 'node:dns'
import { isIP } from 'node:net'
import { Agent, type Response as UndiciResponse, errors, fetch as undiciFetch } from 'undici'
import { isPrivateIp } from './blocklist'
import { SsrfError } from './error'

export { SsrfError } from './error'
export { isPrivateIp } from './blocklist'
export type { Response as UndiciResponse } from 'undici'
export const { ResponseExceededMaxSizeError } = errors

export interface ServerFetchOptions extends RequestInit {
  timeout?: number
  maxResponseSize?: number
  /**
   * Maximum number of redirects to follow before throwing
   * `SsrfError('TOO_MANY_REDIRECTS')`. Defaults to 5 (matching undici). Each hop
   * is re-validated by `validateUrl` (scheme, port, IP). Use
   * `followRedirects: false` to return the 3xx response without following.
   */
  maxRedirects?: number
  /**
   * Redirect-following policy. Every followed hop is re-validated regardless.
   * - `true` (default): follow anywhere that passes validation.
   * - `false`: do not follow — return the 3xx response as-is.
   * - `'same-origin'`: only follow redirects whose origin (scheme + host + port)
   *   matches the original request.
   * - `'same-site'`: only follow redirects to the same registrable domain
   *   (naive eTLD+1; prefer `'same-origin'` for strictness).
   *
   * `Authorization` and `Cookie` headers are stripped on cross-origin hops.
   */
  followRedirects?: 'same-origin' | 'same-site' | boolean
}

export interface ValidatedUrl {
  parsed: URL
  hostname: string
  resolvedIps: string[]
}

const DEFAULT_TIMEOUT = 10_000
export const DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024
const DEFAULT_MAX_REDIRECTS = 5
const ALLOWED_PORTS = new Set([80, 443])
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

/** Naive registrable domain (eTLD+1 by last two labels). */
function registrableDomain(hostname: string): string {
  const labels = hostname.split('.')
  return labels.length <= 2 ? hostname : labels.slice(-2).join('.')
}

function isSameSite(a: URL, b: URL): boolean {
  return registrableDomain(a.hostname) === registrableDomain(b.hostname)
}

/**
 * Custom DNS lookup that rejects private/reserved IPs.
 * Plugs into undici's `connect.lookup` so validation and connection
 * use the same resolved address — no TOCTOU rebinding window.
 */
function ssrfSafeLookup(
  hostname: string,
  options: dns.LookupOptions,
  callback: (
    err: NodeJS.ErrnoException | null,
    addresses: dns.LookupAddress[] | string,
    family?: number,
  ) => void,
) {
  dns.lookup(hostname, options, (err, addresses, family) => {
    if (err) return callback(err, addresses, family)

    if (Array.isArray(addresses)) {
      for (const addr of addresses) {
        if (isPrivateIp(addr.address)) {
          return callback(
            new SsrfError('BLOCKED_IP', `Blocked IP: ${addr.address}`, hostname),
            addresses,
            family,
          )
        }
      }
      return callback(null, addresses, family)
    }

    if (isPrivateIp(addresses)) {
      return callback(
        new SsrfError('BLOCKED_IP', `Blocked IP: ${addresses}`, hostname),
        addresses,
        family,
      )
    }
    callback(null, addresses, family)
  })
}

const ssrfSafeAgent = new Agent({
  connect: { lookup: ssrfSafeLookup },
  maxResponseSize: DEFAULT_MAX_RESPONSE_SIZE,
})

/**
 * Validate that a URL targets only public IPs and uses http(s).
 * Resolves DNS and checks every returned address.
 *
 * **WARNING:** Using this to validate a URL and then passing it to a separate
 * `fetch()` call reintroduces the DNS rebinding TOCTOU window. You should
 * almost always use `serverFetch()` instead. This function exists for
 * registration-time checks (e.g., validating a webhook URL before saving it)
 * where no fetch happens.
 *
 * @throws SsrfError if blocked.
 */
export async function validateUrl(url: string): Promise<ValidatedUrl> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new SsrfError('INVALID_URL', 'Invalid URL', url)
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfError('BLOCKED_PROTOCOL', `Blocked protocol: ${parsed.protocol}`, url)
  }

  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80
  if (!ALLOWED_PORTS.has(port)) {
    throw new SsrfError('BLOCKED_PORT', `Blocked port: ${port}`, url)
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')

  if (isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new SsrfError('BLOCKED_IP', `Blocked IP: ${hostname}`, url)
    }
    return { resolvedIps: [hostname], hostname, parsed }
  }

  let addresses: dns.LookupAddress[]
  try {
    addresses = await dns.promises.lookup(hostname, { all: true })
  } catch {
    throw new SsrfError('DNS_FAILED', `DNS resolution failed for ${hostname}`, url)
  }

  if (addresses.length === 0) {
    throw new SsrfError('DNS_FAILED', `DNS resolved to zero addresses for ${hostname}`, url)
  }

  for (const addr of addresses) {
    if (isPrivateIp(addr.address)) {
      throw new SsrfError('BLOCKED_IP', `Blocked IP: ${addr.address}`, url)
    }
  }

  return {
    resolvedIps: addresses.map((a) => a.address),
    hostname,
    parsed,
  }
}

/**
 * Create an undici Agent with the SSRF-safe DNS lookup baked in.
 * The safe lookup is always applied; options are merged with it, not replacing it.
 */
export function createSsrfSafeAgent(options?: ConstructorParameters<typeof Agent>[0]): Agent {
  const connectOpts = typeof options?.connect === 'object' ? options.connect : {}
  return new Agent({
    ...options,
    connect: { ...connectOpts, lookup: ssrfSafeLookup },
  })
}

/**
 * SSRF-safe fetch.
 *
 * Validates the URL (protocol, port, DNS resolution) then fetches using an
 * undici Agent whose `connect.lookup` rejects private/reserved IPs at connect
 * time. DNS resolution and TCP connect use the same resolved address — no
 * TOCTOU gap, no DNS rebinding possible.
 *
 * Response body size is limited by `maxResponseSize` (default 10 MB).
 * Responses with a `Content-Length` header exceeding the limit are rejected
 * immediately. Chunked responses are enforced by undici's Agent at the
 * HTTP-parser level — undici throws `ResponseExceededMaxSizeError` during
 * body consumption (`.text()`, `.json()`, etc.).
 *
 * Redirects are followed manually (`maxRedirects`, default 5) so every hop is
 * re-validated for scheme, port, and IP — not just the final URL.
 * `followRedirects` constrains the allowed targets (`'same-origin'` /
 * `'same-site'` / `true` / `false`), and `Authorization`/`Cookie` are stripped
 * on cross-origin hops.
 */
export async function serverFetch(
  url: string | URL,
  options: ServerFetchOptions = {},
): Promise<UndiciResponse> {
  const urlString = url.toString()
  const { parsed } = await validateUrl(urlString)

  const maxResponseSize = options.maxResponseSize ?? DEFAULT_MAX_RESPONSE_SIZE
  if (
    maxResponseSize !== Infinity &&
    (maxResponseSize <= 0 || !Number.isInteger(maxResponseSize))
  ) {
    throw new SsrfError(
      'INVALID_OPTION',
      'maxResponseSize must be a positive integer or Infinity',
      urlString,
    )
  }

  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS
  if (maxRedirects < 0 || !Number.isInteger(maxRedirects)) {
    throw new SsrfError('INVALID_OPTION', 'maxRedirects must be a non-negative integer', urlString)
  }
  const followRedirects = options.followRedirects ?? true

  const dispatcher =
    maxResponseSize === DEFAULT_MAX_RESPONSE_SIZE
      ? ssrfSafeAgent
      : new Agent({
          connect: { lookup: ssrfSafeLookup },
          maxResponseSize: maxResponseSize === Infinity ? -1 : maxResponseSize,
        })

  const controller = new AbortController()
  const timeout = options.timeout ?? DEFAULT_TIMEOUT
  const timeoutId = setTimeout(() => controller.abort(), timeout)

  // Manual redirect loop: undici returns the real 3xx response under
  // `redirect: 'manual'` (Location readable), so we re-validate every hop
  // instead of trusting only the final URL. A single timeout/abort bounds the
  // whole chain. `connect.lookup` still guards the IP at each connection.
  const originalUrl = new URL(parsed.href)
  let currentUrl = parsed.href
  let method = (options.method ?? 'GET').toUpperCase()
  let body = options.body
  const headers = new Headers(options.headers as HeadersInit | undefined)
  let redirectCount = 0

  try {
    while (true) {
      const response = await undiciFetch(currentUrl, {
        ...options,
        method,
        body,
        headers,
        redirect: 'manual',
        signal: controller.signal,
        dispatcher,
      })

      const location = REDIRECT_STATUSES.has(response.status)
        ? response.headers.get('location')
        : null

      // Not a redirect we follow → this is the response to return.
      if (!location || followRedirects === false) {
        if (maxResponseSize !== Infinity) {
          const contentLength = response.headers.get('content-length')
          const size = Number(contentLength)
          if (contentLength && Number.isFinite(size) && size > maxResponseSize) {
            await response.body?.cancel()
            throw new SsrfError(
              'RESPONSE_TOO_LARGE',
              `Response Content-Length ${contentLength} exceeds limit of ${maxResponseSize} bytes`,
              urlString,
            )
          }
        }
        return response
      }

      if (redirectCount >= maxRedirects) {
        await response.body?.cancel()
        throw new SsrfError(
          'TOO_MANY_REDIRECTS',
          `Exceeded maxRedirects (${maxRedirects}) following redirects from ${urlString}`,
          urlString,
        )
      }

      let nextUrl: URL
      try {
        nextUrl = new URL(location, currentUrl)
      } catch {
        await response.body?.cancel()
        throw new SsrfError('INVALID_URL', `Invalid redirect Location: ${location}`, currentUrl)
      }

      // Re-validate scheme, port, and IP on the next hop.
      await validateUrl(nextUrl.href)

      if (followRedirects === 'same-origin' && nextUrl.origin !== originalUrl.origin) {
        await response.body?.cancel()
        throw new SsrfError(
          'BLOCKED_REDIRECT',
          `Redirect to ${nextUrl.origin} violates same-origin policy`,
          nextUrl.href,
        )
      }
      if (followRedirects === 'same-site' && !isSameSite(originalUrl, nextUrl)) {
        await response.body?.cancel()
        throw new SsrfError(
          'BLOCKED_REDIRECT',
          `Redirect to ${nextUrl.host} violates same-site policy`,
          nextUrl.href,
        )
      }

      // Drop credential-bearing headers when crossing to a different origin.
      if (nextUrl.origin !== new URL(currentUrl).origin) {
        headers.delete('authorization')
        headers.delete('cookie')
      }

      // 303 — and 301/302 on an unsafe method — switch to GET and drop the body.
      if (
        response.status === 303 ||
        ((response.status === 301 || response.status === 302) &&
          method !== 'GET' &&
          method !== 'HEAD')
      ) {
        method = 'GET'
        body = undefined
        headers.delete('content-type')
        headers.delete('content-length')
      }

      await response.body?.cancel()
      currentUrl = nextUrl.href
      redirectCount++
    }
  } finally {
    clearTimeout(timeoutId)
  }
}
