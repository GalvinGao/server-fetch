# server-fetch

[![CI](https://github.com/GalvinGao/server-fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/GalvinGao/server-fetch/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/server-fetch)](https://www.npmjs.com/package/server-fetch)
[![npm downloads](https://img.shields.io/npm/dm/server-fetch)](https://www.npmjs.com/package/server-fetch)
[![bundle size](https://img.shields.io/bundlephobia/minzip/server-fetch)](https://bundlephobia.com/package/server-fetch)
[![license](https://img.shields.io/npm/l/server-fetch)](https://github.com/GalvinGao/server-fetch/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/server-fetch)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)](https://www.typescriptlang.org)
[![npm provenance](https://img.shields.io/badge/npm-provenance-green)](https://docs.npmjs.com/generating-provenance-statements)
[![codecov](https://codecov.io/gh/GalvinGao/server-fetch/graph/badge.svg)](https://codecov.io/gh/GalvinGao/server-fetch)

<!-- [![Known Vulnerabilities](https://snyk.io/test/github/GalvinGao/server-fetch/badge.svg)](https://snyk.io/test/github/GalvinGao/server-fetch) -->
<!-- [![Socket Badge](https://socket.dev/api/badge/npm/package/server-fetch)](https://socket.dev/npm/package/server-fetch) -->

SSRF-safe `fetch()` for server-side use.

Validates URLs against private/reserved IP ranges, enforces scheme and port restrictions, and — critically — uses undici's `connect.lookup` hook so DNS resolution and TCP connection use the same resolved address. No TOCTOU gap, no DNS rebinding.

## Install

```bash
pnpm add server-fetch undici
```

`undici` is a required peer dependency.

## Usage

```typescript
import { serverFetch } from 'server-fetch'

// Drop-in replacement for fetch() — rejects private IPs at connect time
const res = await serverFetch('https://example.com/api', {
  method: 'POST',
  body: JSON.stringify({ url: userInput }),
  timeout: 5000, // optional, defaults to 10s
})
```

### Validate without fetching

For registration-time checks (e.g., saving a webhook URL):

```typescript
import { validateUrl } from 'server-fetch'

// Resolves DNS and checks all returned addresses
const { hostname, resolvedIps, parsed } = await validateUrl(url)
```

> **Warning:** Using `validateUrl()` then passing the URL to a separate `fetch()` reintroduces the DNS rebinding TOCTOU window. Use `serverFetch()` for actual requests.

### Custom agent

```typescript
import { createSsrfSafeAgent } from 'server-fetch'

// SSRF-safe lookup is always applied; your options are merged in
const agent = createSsrfSafeAgent({ connections: 10 })
```

## What it blocks

**Protocols:** Only `http` and `https` are allowed.

**Ports:** Only 80 and 443.

**IP ranges:**

| IPv4             | Purpose                     |
| ---------------- | --------------------------- |
| `0.0.0.0/8`      | "This network"              |
| `10.0.0.0/8`     | Private (RFC 1918)          |
| `100.64.0.0/10`  | Carrier-grade NAT           |
| `127.0.0.0/8`    | Loopback                    |
| `169.254.0.0/16` | Link-local / cloud metadata |
| `172.16.0.0/12`  | Private (RFC 1918)          |
| `192.0.0.0/24`   | IETF protocol assignments   |
| `192.168.0.0/16` | Private (RFC 1918)          |
| `198.18.0.0/15`  | Benchmarking                |
| `240.0.0.0/4`    | Reserved                    |

| IPv6              | Purpose                 |
| ----------------- | ----------------------- |
| `::1/128`         | Loopback                |
| `::/128`          | Unspecified             |
| `fc00::/7`        | Unique local            |
| `fe80::/10`       | Link-local              |
| `::ffff:0:0:0/96` | SIIT IPv4-translated    |
| `64:ff9b::/96`    | NAT64 well-known prefix |
| `64:ff9b:1::/48`  | NAT64 local-use prefix  |

## Error handling

All rejections throw `SsrfError` with a typed `code`:

```typescript
import { serverFetch, SsrfError } from 'server-fetch'

try {
  await serverFetch(url)
} catch (e) {
  if (e instanceof SsrfError) {
    console.log(e.code) // INVALID_URL | BLOCKED_PROTOCOL | BLOCKED_PORT | BLOCKED_IP | DNS_FAILED
    console.log(e.url) // the offending URL
  }
}
```

## How it works

1. `validateUrl()` parses the URL, checks protocol/port, resolves DNS with `{ all: true }`, and rejects if any address is private.
2. `serverFetch()` calls `validateUrl()` for an early error, then fetches through an undici `Agent` whose `connect.lookup` hook validates the resolved IP _inside the connection handshake_ — the same address that passes validation is the one used for TCP connect. No second DNS query, no rebinding window.

## License

MIT
