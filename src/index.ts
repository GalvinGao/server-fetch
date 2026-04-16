import dns from 'node:dns'
import { isIP } from 'node:net'
import { Agent, fetch as undiciFetch } from 'undici'
import { isPrivateIp } from './blocklist'
import { SsrfError } from './error'

export { SsrfError } from './error'
export { isPrivateIp } from './blocklist'

export interface ServerFetchOptions extends RequestInit {
  timeout?: number
}

export interface ValidatedUrl {
  parsed: URL
  hostname: string
  resolvedIps: string[]
}

const DEFAULT_TIMEOUT = 10_000
const ALLOWED_PORTS = new Set([80, 443])

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
 */
export async function serverFetch(
  url: string | URL,
  options: ServerFetchOptions = {},
): Promise<Response> {
  const urlString = url.toString()
  const { parsed } = await validateUrl(urlString)

  const controller = new AbortController()
  const timeout = options.timeout ?? DEFAULT_TIMEOUT
  const timeoutId = setTimeout(() => controller.abort(), timeout)

  try {
    const response = await undiciFetch(parsed.href, {
      ...options,
      signal: controller.signal,
      dispatcher: ssrfSafeAgent,
    })
    return response
  } finally {
    clearTimeout(timeoutId)
  }
}

export default serverFetch
