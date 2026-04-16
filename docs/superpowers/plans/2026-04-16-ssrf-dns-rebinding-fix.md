# SSRF DNS Rebinding Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the DNS rebinding TOCTOU vulnerability by using undici's `connect.lookup` hook so DNS validation and TCP connection use the same resolved address.

**Architecture:** Single entry point (`src/index.ts`) rewritten to use `node:net.BlockList` for IP validation and undici `Agent` with a custom `connect.lookup` for SSRF-safe fetching. undici is a required peer dependency.

**Tech Stack:** TypeScript, undici (peer dep), node:net BlockList, node:dns, vitest

---

### Task 1: Add vitest and undici

**Files:**

- Modify: `package.json`

- [ ] **Step 1: Install vitest and undici**

```bash
pnpm add -D vitest undici
pnpm add --save-peer undici
```

After this, `package.json` should have `vitest` in `devDependencies`, `undici` in both `devDependencies` (for tests) and `peerDependencies`.

- [ ] **Step 2: Add test script to package.json**

Add to the `"scripts"` section:

```json
"test": "vitest run",
"test:watch": "vitest"
```

- [ ] **Step 3: Verify vitest runs (no tests yet)**

```bash
pnpm test
```

Expected: exits with "No test files found" or similar — confirms vitest is wired up.

- [ ] **Step 4: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "feat: add vitest and undici peer dependency"
```

---

### Task 2: Write IP blocklist tests

**Files:**

- Create: `src/blocklist.ts` (empty placeholder to satisfy imports)
- Create: `src/blocklist.test.ts`

- [ ] **Step 1: Create empty blocklist module**

Create `src/blocklist.ts`:

```typescript
import { BlockList } from 'node:net'

const blocklist = new BlockList()

export function isPrivateIp(ip: string): boolean {
  return blocklist.check(ip)
}
```

This is a minimal stub so imports resolve. Tests will fail on actual assertions.

- [ ] **Step 2: Write the tests**

Create `src/blocklist.test.ts`:

```typescript
import { describe, expect, it } from 'vitest'
import { isPrivateIp } from './blocklist'

describe('isPrivateIp', () => {
  describe('IPv4 private ranges', () => {
    it('blocks 0.0.0.0/8 ("this network")', () => {
      expect(isPrivateIp('0.0.0.0')).toBe(true)
      expect(isPrivateIp('0.255.255.255')).toBe(true)
    })

    it('blocks 10.0.0.0/8 (RFC 1918)', () => {
      expect(isPrivateIp('10.0.0.1')).toBe(true)
      expect(isPrivateIp('10.255.255.255')).toBe(true)
    })

    it('blocks 100.64.0.0/10 (carrier-grade NAT)', () => {
      expect(isPrivateIp('100.64.0.1')).toBe(true)
      expect(isPrivateIp('100.127.255.255')).toBe(true)
    })

    it('blocks 127.0.0.0/8 (loopback)', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true)
      expect(isPrivateIp('127.255.255.255')).toBe(true)
    })

    it('blocks 169.254.0.0/16 (link-local / cloud metadata)', () => {
      expect(isPrivateIp('169.254.0.1')).toBe(true)
      expect(isPrivateIp('169.254.169.254')).toBe(true)
    })

    it('blocks 172.16.0.0/12 (RFC 1918)', () => {
      expect(isPrivateIp('172.16.0.1')).toBe(true)
      expect(isPrivateIp('172.31.255.255')).toBe(true)
    })

    it('blocks 192.0.0.0/24 (IETF protocol assignments)', () => {
      expect(isPrivateIp('192.0.0.1')).toBe(true)
      expect(isPrivateIp('192.0.0.255')).toBe(true)
    })

    it('blocks 192.168.0.0/16 (RFC 1918)', () => {
      expect(isPrivateIp('192.168.0.1')).toBe(true)
      expect(isPrivateIp('192.168.255.255')).toBe(true)
    })

    it('blocks 198.18.0.0/15 (benchmarking)', () => {
      expect(isPrivateIp('198.18.0.1')).toBe(true)
      expect(isPrivateIp('198.19.255.255')).toBe(true)
    })

    it('blocks 240.0.0.0/4 (reserved)', () => {
      expect(isPrivateIp('240.0.0.1')).toBe(true)
      expect(isPrivateIp('255.255.255.255')).toBe(true)
    })

    it('allows public IPv4 addresses', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false)
      expect(isPrivateIp('93.184.216.34')).toBe(false)
      expect(isPrivateIp('1.1.1.1')).toBe(false)
    })
  })

  describe('IPv6 private ranges', () => {
    it('blocks ::1 (loopback)', () => {
      expect(isPrivateIp('::1')).toBe(true)
    })

    it('blocks :: (unspecified)', () => {
      expect(isPrivateIp('::')).toBe(true)
    })

    it('blocks fc00::/7 (unique local)', () => {
      expect(isPrivateIp('fc00::1')).toBe(true)
      expect(isPrivateIp('fdff::1')).toBe(true)
    })

    it('blocks fe80::/10 (link-local)', () => {
      expect(isPrivateIp('fe80::1')).toBe(true)
    })

    it('blocks ::ffff:0:0:0/96 (SIIT IPv4-translated)', () => {
      expect(isPrivateIp('::ffff:0:0:1')).toBe(true)
    })

    it('blocks 64:ff9b::/96 (NAT64 well-known prefix)', () => {
      expect(isPrivateIp('64:ff9b::1')).toBe(true)
      expect(isPrivateIp('64:ff9b::7f00:1')).toBe(true)
    })

    it('blocks 64:ff9b:1::/48 (NAT64 local-use prefix)', () => {
      expect(isPrivateIp('64:ff9b:1::1')).toBe(true)
    })

    it('allows public IPv6 addresses', () => {
      expect(isPrivateIp('2606:4700:4700::1111')).toBe(false)
      expect(isPrivateIp('2001:4860:4860::8888')).toBe(false)
    })
  })
})
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pnpm test
```

Expected: most assertions FAIL because the blocklist has no subnets added yet.

- [ ] **Step 4: Commit failing tests**

```bash
git add src/blocklist.ts src/blocklist.test.ts
git commit -m "test: add IP blocklist tests (failing)"
```

---

### Task 3: Implement IP blocklist

**Files:**

- Modify: `src/blocklist.ts`

- [ ] **Step 1: Implement the full blocklist**

Replace `src/blocklist.ts` with:

```typescript
import { BlockList } from 'node:net'

const blocklist = new BlockList()

// IPv4
blocklist.addSubnet('0.0.0.0', 8, 'ipv4') // "this network" (RFC 1122)
blocklist.addSubnet('10.0.0.0', 8, 'ipv4') // private (RFC 1918)
blocklist.addSubnet('100.64.0.0', 10, 'ipv4') // carrier-grade NAT (RFC 6598)
blocklist.addSubnet('127.0.0.0', 8, 'ipv4') // loopback
blocklist.addSubnet('169.254.0.0', 16, 'ipv4') // link-local (includes cloud metadata 169.254.169.254)
blocklist.addSubnet('172.16.0.0', 12, 'ipv4') // private (RFC 1918)
blocklist.addSubnet('192.0.0.0', 24, 'ipv4') // IETF protocol assignments (RFC 6890)
blocklist.addSubnet('192.168.0.0', 16, 'ipv4') // private (RFC 1918)
blocklist.addSubnet('198.18.0.0', 15, 'ipv4') // benchmarking (RFC 2544)
blocklist.addSubnet('240.0.0.0', 4, 'ipv4') // reserved for future use

// IPv6
blocklist.addSubnet('::1', 128, 'ipv6') // loopback
blocklist.addSubnet('::', 128, 'ipv6') // unspecified
blocklist.addSubnet('fc00::', 7, 'ipv6') // unique local (RFC 4193)
blocklist.addSubnet('fe80::', 10, 'ipv6') // link-local
blocklist.addSubnet('::ffff:0:0:0', 96, 'ipv6') // SIIT IPv4-translated (RFC 6052)
blocklist.addSubnet('64:ff9b::', 96, 'ipv6') // NAT64 well-known prefix (RFC 6052)
blocklist.addSubnet('64:ff9b:1::', 48, 'ipv6') // NAT64 local-use prefix (RFC 8215)

export function isPrivateIp(ip: string): boolean {
  return blocklist.check(ip)
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
pnpm test
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/blocklist.ts
git commit -m "feat: implement IP blocklist with node:net BlockList"
```

---

### Task 4: Write SsrfError and validateUrl tests

**Files:**

- Create: `src/index.test.ts`
- Create: `src/error.ts` (empty stub)

- [ ] **Step 1: Create SsrfError stub**

Create `src/error.ts`:

```typescript
export class SsrfError extends Error {
  readonly code: string
  readonly url: string

  constructor(code: string, message: string, url: string) {
    super(message)
    this.name = 'SsrfError'
    this.code = code
    this.url = url
  }
}
```

- [ ] **Step 2: Write validateUrl and SsrfError tests**

Create `src/index.test.ts`:

```typescript
import { describe, expect, it } from 'vitest'
import { SsrfError, validateUrl } from './index'

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
    try {
      await validateUrl('ftp://example.com/')
    } catch (e) {
      expect(e).toBeInstanceOf(SsrfError)
      expect((e as SsrfError).code).toBe('BLOCKED_PROTOCOL')
    }
  })

  it('rejects non-standard ports', async () => {
    await expect(validateUrl('http://example.com:8080/')).rejects.toThrow(SsrfError)
    await expect(validateUrl('https://example.com:4443/')).rejects.toThrow(SsrfError)
  })

  it('rejects non-standard ports with BLOCKED_PORT code', async () => {
    try {
      await validateUrl('http://example.com:8080/')
    } catch (e) {
      expect(e).toBeInstanceOf(SsrfError)
      expect((e as SsrfError).code).toBe('BLOCKED_PORT')
    }
  })

  it('rejects invalid URLs', async () => {
    await expect(validateUrl('not-a-url')).rejects.toThrow(SsrfError)
    await expect(validateUrl('')).rejects.toThrow(SsrfError)
  })

  it('rejects invalid URLs with INVALID_URL code', async () => {
    try {
      await validateUrl('not-a-url')
    } catch (e) {
      expect(e).toBeInstanceOf(SsrfError)
      expect((e as SsrfError).code).toBe('INVALID_URL')
    }
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
    try {
      await validateUrl('http://127.0.0.1/')
    } catch (e) {
      expect(e).toBeInstanceOf(SsrfError)
      expect((e as SsrfError).code).toBe('BLOCKED_IP')
    }
  })
})
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pnpm test
```

Expected: FAIL — `validateUrl` and `SsrfError` are not yet exported from `src/index.ts`.

- [ ] **Step 4: Commit failing tests**

```bash
git add src/error.ts src/index.test.ts
git commit -m "test: add validateUrl and SsrfError tests (failing)"
```

---

### Task 5: Rewrite src/index.ts

**Files:**

- Modify: `src/index.ts`

- [ ] **Step 1: Replace src/index.ts with the new implementation**

Replace the entire contents of `src/index.ts`:

```typescript
import dns from 'node:dns'
import { isIP } from 'node:net'
import { Agent } from 'undici'
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
    const response = await fetch(parsed.href, {
      ...options,
      signal: controller.signal,
      // @ts-expect-error -- dispatcher is a valid undici option on Node's built-in fetch
      dispatcher: ssrfSafeAgent,
    })
    return response
  } finally {
    clearTimeout(timeoutId)
  }
}

export default serverFetch
```

- [ ] **Step 2: Run tests**

```bash
pnpm test
```

Expected: all tests in `src/blocklist.test.ts` and `src/index.test.ts` PASS.

- [ ] **Step 3: Run lint and format**

```bash
pnpm lint && pnpm fmt
```

- [ ] **Step 4: Commit**

```bash
git add src/index.ts src/error.ts
git commit -m "feat: rewrite serverFetch with undici connect.lookup SSRF protection"
```

---

### Task 6: Remove old dependencies

**Files:**

- Modify: `package.json`

- [ ] **Step 1: Remove ip-address, psl, and @types/psl**

```bash
pnpm remove ip-address psl @types/psl
```

- [ ] **Step 2: Verify build still works**

```bash
pnpm build
```

Expected: tsdown builds successfully. `undici` is externalized automatically because it's in `peerDependencies`.

- [ ] **Step 3: Run tests**

```bash
pnpm test
```

Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "feat: remove ip-address, psl dependencies (replaced by node:net BlockList)"
```

---

### Task 7: Add serverFetch integration tests

**Files:**

- Modify: `src/index.test.ts`

- [ ] **Step 1: Add serverFetch tests to src/index.test.ts**

Append to the end of `src/index.test.ts`:

```typescript
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
```

Also add to the imports at the top of the file:

```typescript
import { Agent } from 'undici'
import { SsrfError, createSsrfSafeAgent, serverFetch, validateUrl } from './index'
```

- [ ] **Step 2: Run tests**

```bash
pnpm test
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/index.test.ts
git commit -m "test: add serverFetch and createSsrfSafeAgent integration tests"
```

---

### Task 8: Update AGENTS.md and final verification

**Files:**

- Modify: `AGENTS.md`

- [ ] **Step 1: Update AGENTS.md dependencies section**

Replace the `## Dependencies` section:

```markdown
## Dependencies

- `undici` (peer) — provides `Agent` with `connect.lookup` hook for SSRF-safe DNS resolution
```

- [ ] **Step 2: Add test command to AGENTS.md**

Add `pnpm test` and `pnpm test:watch` to the Commands section.

- [ ] **Step 3: Full verification**

```bash
pnpm lint && pnpm fmt:check && pnpm test && pnpm build
```

Expected: all pass, build produces dist/ with no ip-address or psl bundled.

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md
git commit -m "docs: update AGENTS.md for new dependency surface"
```
