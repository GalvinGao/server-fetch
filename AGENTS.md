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
  index.ts    # Single entry point — exports serverFetch()
```

## Dependencies

- `ip-address` — IPv4/IPv6 parsing and subnet matching
- `psl` — Public Suffix List validation for hostnames
