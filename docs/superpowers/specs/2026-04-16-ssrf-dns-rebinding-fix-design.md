# SSRF DNS Rebinding Fix

Fix the TOCTOU (Time-of-Check, Time-of-Use) DNS rebinding vulnerability in `serverFetch` by adopting undici's `connect.lookup` pattern, hardening the IP blocklist, and removing unnecessary dependencies.

## Problem

The current implementation validates DNS in `validateUrl()` then passes the URL to `fetch()`, which resolves DNS independently. An attacker controlling their DNS server can return a public IP for the first resolution (passes validation) and a private IP for the second (reaches internal network). This is a classic DNS rebinding attack.

Additionally, the IPv6 blocklist is missing SIIT and NAT64 translation ranges, allowing bypass via addresses like `[64:ff9b::7f00:1]` (127.0.0.1 via NAT64).

## Solution

Use undici's `Agent` with a custom `connect.lookup` hook. The hook intercepts DNS resolution inside the TCP connection handshake, so the same resolved IP that's validated is the one used to connect. No second DNS query, no rebinding window.

undici is declared as a required peer dependency to keep the package lightweight while making the requirement explicit. A security library should not silently degrade to a vulnerable mode.

## Architecture

Single entry point (`src/index.ts`). Key changes:

1. **IP validation**: Switch from `ip-address` + manual subnet iteration to `node:net.BlockList`. Simpler, no dependency, handles IPv4/IPv6 canonicalization natively.
2. **DNS-safe fetch**: Shared undici `Agent` with `connect.lookup` that rejects private IPs at connect time.
3. **`validateUrl()`**: Standalone export for pre-validation (e.g., webhook registration). Resolves DNS with `{ all: true }` and checks every address.
4. **`serverFetch()`**: Calls `validateUrl()` for early errors, then fetches through the safe agent for connect-time enforcement.

## Dependency changes

- **Remove**: `ip-address`, `psl`, `@types/psl`
- **Add**: `undici` as `peerDependencies` (required)

`psl` was used for hostname validation but URL parsing + DNS resolution already cover that — if a hostname doesn't resolve, it's rejected. The PSL check added false negatives (rejecting valid IPs in URL form) without security benefit.

## IP blocklist

All private/reserved ranges checked via `node:net.BlockList`.

### IPv4

| Range            | Purpose                                             |
| ---------------- | --------------------------------------------------- |
| `0.0.0.0/8`      | "This network" (RFC 1122)                           |
| `10.0.0.0/8`     | Private (RFC 1918)                                  |
| `100.64.0.0/10`  | Carrier-grade NAT (RFC 6598)                        |
| `127.0.0.0/8`    | Loopback                                            |
| `169.254.0.0/16` | Link-local, includes cloud metadata 169.254.169.254 |
| `172.16.0.0/12`  | Private (RFC 1918)                                  |
| `192.0.0.0/24`   | IETF protocol assignments (RFC 6890)                |
| `192.168.0.0/16` | Private (RFC 1918)                                  |
| `198.18.0.0/15`  | Benchmarking (RFC 2544)                             |
| `240.0.0.0/4`    | Reserved for future use                             |

### IPv6

| Range             | Purpose                            |
| ----------------- | ---------------------------------- |
| `::1/128`         | Loopback                           |
| `::/128`          | Unspecified                        |
| `fc00::/7`        | Unique local (RFC 4193)            |
| `fe80::/10`       | Link-local                         |
| `::ffff:0:0:0/96` | SIIT IPv4-translated (RFC 6052)    |
| `64:ff9b::/96`    | NAT64 well-known prefix (RFC 6052) |
| `64:ff9b:1::/48`  | NAT64 local-use prefix (RFC 8215)  |

The dedicated `AWS_IMDS_ENDPOINT` check is removed — `169.254.0.0/16` already covers it.

## Error handling

Typed `SsrfError` class replacing generic `Error`:

```typescript
export class SsrfError extends Error {
  readonly code: string
  readonly url: string
  constructor(code: string, message: string, url: string)
}
```

Error codes:

- `INVALID_URL` — unparseable URL
- `BLOCKED_PROTOCOL` — not http/https
- `BLOCKED_PORT` — not 80/443
- `BLOCKED_IP` — resolved to private/reserved range
- `DNS_FAILED` — hostname didn't resolve
- `UNDICI_MISSING` — undici not installed

## Exports

```typescript
// Primary API — drop-in fetch replacement
export async function serverFetch(url: string | URL, options?: ServerFetchOptions): Promise<Response>
export default serverFetch

// Pre-validation for registration flows
// WARNING: Using validateUrl() result to drive a separate fetch() reintroduces the
// DNS rebinding TOCTOU window. You should almost always use serverFetch() instead.
// This export exists for registration-time checks (e.g., validating a webhook URL
// before saving it) where no fetch happens.
export async function validateUrl(url: string): Promise<ValidatedUrl>

// Error class for instanceof checks
export class SsrfError extends Error

// Escape hatch for custom agent config (safe lookup is always applied;
// options are merged with the SSRF-safe connect.lookup, not replacing it)
export function createSsrfSafeAgent(options?: AgentOptions): Agent
```

## Timeout

No changes. The existing `AbortController` + `setTimeout` pattern works correctly.

## ValidatedUrl return type

```typescript
interface ValidatedUrl {
  parsed: URL
  hostname: string
  resolvedIps: string[]
}
```

Returns the parsed URL, extracted hostname, and all resolved IP addresses for consumer inspection.
