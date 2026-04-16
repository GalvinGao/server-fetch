# server-fetch

SSRF-safe `fetch()` wrapper for server-side use. Validates URLs against private network ranges, enforces scheme/port restrictions, and applies timeouts.

## Stack

- **Runtime:** Node.js (ESM)
- **Language:** TypeScript (strict mode)
- **Build:** tsdown (ESM + CJS dual output)
- **Lint:** oxlint
- **Format:** oxfmt (no semi, single quotes)
- **Package manager:** pnpm
- **Pre-commit hooks:** prek (oxfmt + oxlint)

## Commands

```bash
pnpm build        # Build with tsdown
pnpm dev          # Watch mode
pnpm lint         # Run oxlint
pnpm lint:fix     # Run oxlint with auto-fix
pnpm fmt          # Format with oxfmt
pnpm fmt:check    # Check formatting
pnpm test         # Run tests with vitest
pnpm test:watch   # Run tests in watch mode
```

## Code style

- No semicolons
- Single quotes
- Trailing commas everywhere
- 100 char line width
- 2-space indent

## Project structure

```
src/
  index.ts          # Entry point — exports serverFetch(), validateUrl(), createSsrfSafeAgent()
  blocklist.ts      # IP blocklist using node:net BlockList (IPv4 + IPv6 ranges)
  error.ts          # SsrfError class with typed error codes
  index.test.ts     # Tests for validateUrl, serverFetch, createSsrfSafeAgent
  blocklist.test.ts # Tests for IP range blocking (19 ranges + bypass vectors)
```

## Dependencies

- `undici` (peer) — provides `Agent` with `connect.lookup` hook for SSRF-safe DNS resolution
