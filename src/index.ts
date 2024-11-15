import { Address4, Address6 } from 'ip-address'
import { lookup } from 'node:dns/promises'
import { URL } from 'node:url'
import publicSuffixList from 'psl'

interface ServerFetchOptions extends RequestInit {
  timeout?: number
}

const DEFAULT_TIMEOUT = 10_000 // 10 seconds
const ALLOWED_PORTS = new Set([80, 443])
const ALLOWED_SCHEMES = new Set(['http', 'https'])
const AWS_IMDS_ENDPOINT = '169.254.169.254'

// Helper function to normalize IP addresses
function normalizeIP(ip: string): string {
  try {
    // Handle IPv4-mapped IPv6 addresses
    if (ip.includes(':')) {
      const addr6 = new Address6(ip)
      if (addr6.is4()) {
        return new Address4(addr6.to4().address).correctForm()
      }
      return addr6.correctForm()
    }
    // Handle regular IPv4
    return new Address4(ip).correctForm()
  } catch {
    throw new Error(`Invalid IP address: ${ip}`)
  }
}

// Private network ranges from IANA list
const PRIVATE_IPV4_RANGES = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '240.0.0.0/4',
]

const PRIVATE_IPV6_RANGES = ['::1/128', '::/128', 'fc00::/7', 'fe80::/10']

async function isPrivateHostname(hostname: string): Promise<boolean> {
  try {
    const ip = await lookup(hostname)
    const normalizedIP = normalizeIP(ip.address)

    if (ip.family === 4) {
      const addr = new Address4(normalizedIP)
      if (normalizedIP === AWS_IMDS_ENDPOINT) {
        return true
      }

      return PRIVATE_IPV4_RANGES.some((range) => addr.isInSubnet(new Address4(range)))
    } else {
      const addr = new Address6(normalizedIP)
      return PRIVATE_IPV6_RANGES.some((range) => addr.isInSubnet(new Address6(range)))
    }
  } catch {
    throw new Error(`Invalid hostname: ${hostname}`)
  }
}

async function validateUrl(urlString: string): Promise<URL> {
  const url = new URL(urlString)

  // Validate scheme
  if (!ALLOWED_SCHEMES.has(url.protocol.slice(0, -1))) {
    throw new Error(`Invalid scheme: ${url.protocol}`)
  }

  // Validate port
  const port = url.port ? parseInt(url.port, 10) : url.protocol === 'https:' ? 443 : 80
  if (!ALLOWED_PORTS.has(port)) {
    throw new Error(`Invalid port: ${port}`)
  }

  // Validate hostname against public suffix list
  if (!publicSuffixList.isValid(url.hostname)) {
    throw new Error(`Invalid hostname: ${url.hostname}`)
  }

  // Check for private network
  if (await isPrivateHostname(url.hostname)) {
    throw new Error('Private network addresses are not allowed')
  }

  return url
}

export async function serverFetch(
  url: string | URL,
  options: ServerFetchOptions = {}
): Promise<Response> {
  const urlString = url.toString()
  const validatedUrl = await validateUrl(urlString)

  const controller = new AbortController()
  const timeout = options.timeout ?? DEFAULT_TIMEOUT
  const timeoutId = setTimeout(() => controller.abort(), timeout)

  try {
    const response = await fetch(validatedUrl, {
      ...options,
      signal: controller.signal,
    })
    return response
  } finally {
    clearTimeout(timeoutId)
  }
}

export default serverFetch
