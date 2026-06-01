# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> `CLAUDE.md` is a symlink to this file — edit `AGENTS.md`.

## What this is

SSRF-safe `fetch()` wrapper for server-side Node.js. Validates URLs against private/reserved IP ranges, enforces scheme/port, and caps response size.

## Stack

- **Runtime:** Node.js `>=20.18.1`, ESM-first (dual ESM + CJS output via tsdown)
- **Language:** TypeScript strict mode
- **Lint / format:** oxlint + oxfmt (no semis, single quotes, trailing commas, 100 cols, 2-space indent)
- **Package manager:** pnpm
- **Tests:** vitest (v8 coverage)
- **Pre-commit:** prek runs oxfmt + oxlint (see `prek.toml`)

## Commands

```bash
pnpm build              # Bundle with tsdown (clean + sourcemaps + minify + .d.ts)
pnpm dev                # tsdown --watch
pnpm test               # vitest run
pnpm test:watch         # vitest watch mode
pnpm test -- <pattern>  # Run a single test file, e.g. `pnpm test -- blocklist`
pnpm lint / lint:fix
pnpm fmt / fmt:check
```

## Architecture

The security property this library provides is: **the IP that passes validation is the same IP used for the TCP connection**. Understand this before modifying any fetch/agent/DNS code — the obvious refactor almost always breaks it.

- `validateUrl()` in `src/index.ts` checks protocol, port, and does a literal-IP check _or_ a `dns.promises.lookup(..., { all: true })` — it surfaces a fast, typed error before any network activity.
- `serverFetch()` does the same validation (for the early error), then dispatches via an undici `Agent` whose `connect.lookup` hook re-runs the blocklist check _inside the connection handshake_. This is the anti-DNS-rebinding / anti-TOCTOU guarantee: there is no second DNS query between "validated" and "connected."
- Using `validateUrl()` alone and then calling plain `fetch()` reintroduces the TOCTOU window. The JSDoc on `validateUrl` says so; keep that warning intact.

### Agent instances

`src/index.ts` keeps a module-level `ssrfSafeAgent` with the default `maxResponseSize`. `serverFetch()` reuses it when the caller accepts the default, and only constructs a fresh `Agent` per-call when a custom `maxResponseSize` is supplied. Don't convert this to "one Agent per call" — it breaks connection pooling.

### Response size enforcement (two layers)

1. **Pre-check:** if the response has a `Content-Length` header exceeding the limit, the body is cancelled and `SsrfError('RESPONSE_TOO_LARGE')` is thrown synchronously after headers arrive.
2. **Streaming enforcement:** for chunked / missing-Content-Length responses, undici's Agent enforces the cap at the HTTP parser and throws `ResponseExceededMaxSizeError` during body consumption (`.text()`, `.json()`, etc.). This error is re-exported from the entry point.

`maxResponseSize: Infinity` disables the limit (mapped to undici's `-1` internally). Any other non-positive-integer value must throw `SsrfError('INVALID_OPTION')`.

### Redirect handling

`serverFetch()` follows redirects with a **manual loop** (`redirect: 'manual'`), not undici's built-in following. undici surfaces the real 3xx response (status + readable `Location`) under manual mode, so every hop is re-run through `validateUrl()` — scheme, port, and IP — not just the final URL. `connect.lookup` still guards the IP at each connection, so rebinding across hops is covered too. `maxRedirects` (default 5) caps the chain (`TOO_MANY_REDIRECTS`); `followRedirects` (`'same-origin' | 'same-site' | true | false`) constrains targets (`BLOCKED_REDIRECT`). `Authorization`/`Cookie` are stripped on cross-origin hops, and 303 (and 301/302 on unsafe methods) downgrade to GET and drop the body. One `AbortController`/timeout bounds the whole chain. Don't replace this with undici's redirect interceptor — it can't re-validate scheme/port or enforce same-origin/same-site.

### Blocklist

`src/blocklist.ts` uses `node:net` `BlockList` with 10 IPv4 + 7 IPv6 ranges. Any new range goes here with an RFC comment, and a corresponding case in `src/blocklist.test.ts`. The list covers cloud metadata (`169.254.169.254` via `169.254.0.0/16`), NAT64 prefixes, and SIIT — bypass vectors worth preserving tests for.

### Error model

`SsrfError` has a string `code` and the offending `url`. Current codes: `INVALID_URL`, `BLOCKED_PROTOCOL`, `BLOCKED_PORT`, `BLOCKED_IP`, `DNS_FAILED`, `RESPONSE_TOO_LARGE`, `TOO_MANY_REDIRECTS`, `BLOCKED_REDIRECT`, `INVALID_OPTION`. Add new codes here and document them in `README.md`.

## Project structure

```
src/
  index.ts          # serverFetch, validateUrl, createSsrfSafeAgent, ssrfSafeLookup, re-exports
  blocklist.ts      # node:net BlockList (IPv4 + IPv6 reserved ranges)
  error.ts          # SsrfError class
  *.test.ts         # vitest colocated tests
```

## Dependencies

`undici` is a **peer dependency** — do not move it to `dependencies`. It provides the `Agent` and `connect.lookup` hook the whole design depends on.
