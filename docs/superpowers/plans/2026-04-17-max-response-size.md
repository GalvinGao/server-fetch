# Max Response Size Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a configurable `maxResponseSize` option to `serverFetch()` that prevents memory exhaustion from large responses, using undici's built-in Agent enforcement plus a Content-Length pre-check.

**Architecture:** Two-layer enforcement. Layer 1: Content-Length header pre-check in `serverFetch()` throws `SsrfError('RESPONSE_TOO_LARGE', ...)` immediately for known-size responses. Layer 2: undici Agent's `maxResponseSize` enforces the limit per-chunk during body parsing for chunked/streaming responses. Per-request agents are created when the caller specifies a non-default limit.

**Tech Stack:** TypeScript, undici (peer dep, v8.1.0+), vitest

---

## File Structure

- **Modify:** `src/index.ts` — Add `maxResponseSize` to `ServerFetchOptions`, export `DEFAULT_MAX_RESPONSE_SIZE`, update `ssrfSafeAgent` with default limit, add Content-Length pre-check + per-request agent logic in `serverFetch()`, re-export `errors` from undici
- **Modify:** `src/index.test.ts` — Add tests for Content-Length pre-check, custom maxResponseSize, Infinity disabling

---

### Task 1: Exports, constant, and interface update

**Files:**

- Modify: `src/index.ts:1-22` (imports, exports, interface, constants)
- Test: `src/index.test.ts`

- [ ] **Step 1: Write the failing test for DEFAULT_MAX_RESPONSE_SIZE export**

Add to `src/index.test.ts` at the top, updating the import and adding a test:

```ts
// Update import line (line 4) to:
import {
  DEFAULT_MAX_RESPONSE_SIZE,
  SsrfError,
  createSsrfSafeAgent,
  serverFetch,
  validateUrl,
} from './index'

// Add new describe block after the SsrfError describe:
describe('DEFAULT_MAX_RESPONSE_SIZE', () => {
  it('is 10MB', () => {
    expect(DEFAULT_MAX_RESPONSE_SIZE).toBe(10 * 1024 * 1024)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test -- --reporter=verbose 2>&1 | head -30`
Expected: FAIL — `DEFAULT_MAX_RESPONSE_SIZE` is not exported

- [ ] **Step 3: Add the constant, update the interface, and add exports**

In `src/index.ts`:

Update the import from undici (line 3) to also import `errors`:

```ts
import { Agent, type Response as UndiciResponse, errors, fetch as undiciFetch } from 'undici'
```

Add re-export after the existing exports (after line 9):

```ts
export const { ResponseExceededMaxSizeError } = errors
```

Add the constant after `DEFAULT_TIMEOUT` (after line 21):

```ts
export const DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024
```

Update the `ServerFetchOptions` interface (lines 11-13) to:

```ts
export interface ServerFetchOptions extends RequestInit {
  timeout?: number
  maxResponseSize?: number
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test -- --reporter=verbose 2>&1 | head -40`
Expected: PASS — all tests pass including the new one

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "feat: add DEFAULT_MAX_RESPONSE_SIZE constant and maxResponseSize option type"
```

---

### Task 2: Content-Length pre-check in serverFetch

**Files:**

- Modify: `src/index.ts:151-172` (serverFetch function)
- Test: `src/index.test.ts`

- [ ] **Step 1: Write the failing test for Content-Length pre-check**

Add to the `serverFetch` describe block in `src/index.test.ts`:

```ts
it('rejects when Content-Length exceeds default maxResponseSize', async () => {
  const hugeContentLength = (DEFAULT_MAX_RESPONSE_SIZE + 1).toString()
  const fetchSpy = vi.spyOn(await import('undici'), 'fetch').mockResolvedValueOnce({
    headers: new Headers({ 'content-length': hugeContentLength }),
    body: { cancel: vi.fn() },
  } as any)

  const err = await serverFetch('https://example.com', { timeout: 2000 }).catch((e) => e)
  fetchSpy.mockRestore()

  expect(err).toBeInstanceOf(SsrfError)
  expect(err.code).toBe('RESPONSE_TOO_LARGE')
  expect(err.message).toContain(hugeContentLength)
})

it('rejects when Content-Length exceeds custom maxResponseSize', async () => {
  const fetchSpy = vi.spyOn(await import('undici'), 'fetch').mockResolvedValueOnce({
    headers: new Headers({ 'content-length': '2000' }),
    body: { cancel: vi.fn() },
  } as any)

  const err = await serverFetch('https://example.com', {
    timeout: 2000,
    maxResponseSize: 1000,
  }).catch((e) => e)
  fetchSpy.mockRestore()

  expect(err).toBeInstanceOf(SsrfError)
  expect(err.code).toBe('RESPONSE_TOO_LARGE')
})

it('allows responses within maxResponseSize', async () => {
  const res = await serverFetch('https://example.com', { timeout: 5000 })
  expect(res.status).toBe(200)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm test -- --reporter=verbose 2>&1 | tail -30`
Expected: FAIL — Content-Length pre-check not implemented yet (the mock response will be returned as-is)

- [ ] **Step 3: Implement Content-Length pre-check and agent management in serverFetch**

Replace the `serverFetch` function in `src/index.ts` (lines 143-172) with:

```ts
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
 */
export async function serverFetch(
  url: string | URL,
  options: ServerFetchOptions = {},
): Promise<UndiciResponse> {
  const urlString = url.toString()
  const { parsed } = await validateUrl(urlString)

  const maxResponseSize = options.maxResponseSize ?? DEFAULT_MAX_RESPONSE_SIZE
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

  try {
    const response = await undiciFetch(parsed.href, {
      ...options,
      signal: controller.signal,
      dispatcher,
    })

    if (maxResponseSize !== Infinity) {
      const contentLength = response.headers.get('content-length')
      if (contentLength && parseInt(contentLength, 10) > maxResponseSize) {
        await response.body?.cancel()
        throw new SsrfError(
          'RESPONSE_TOO_LARGE',
          `Response Content-Length ${contentLength} exceeds limit of ${maxResponseSize} bytes`,
          urlString,
        )
      }
    }

    return response
  } finally {
    clearTimeout(timeoutId)
  }
}
```

Also update the module-level `ssrfSafeAgent` (line 65-67) to include the default limit:

```ts
const ssrfSafeAgent = new Agent({
  connect: { lookup: ssrfSafeLookup },
  maxResponseSize: DEFAULT_MAX_RESPONSE_SIZE,
})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test -- --reporter=verbose 2>&1 | tail -40`
Expected: PASS — all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "feat: add Content-Length pre-check and agent management for maxResponseSize"
```

---

### Task 3: Test Infinity disables the limit

**Files:**

- Test: `src/index.test.ts`

- [ ] **Step 1: Write the test for Infinity disabling the limit**

Add to the `serverFetch` describe block in `src/index.test.ts`:

```ts
it('disables size limit when maxResponseSize is Infinity', async () => {
  const fetchSpy = vi.spyOn(await import('undici'), 'fetch').mockResolvedValueOnce({
    status: 200,
    headers: new Headers({ 'content-length': '999999999999' }),
    body: null,
  } as any)

  const res = await serverFetch('https://example.com', {
    timeout: 2000,
    maxResponseSize: Infinity,
  })
  fetchSpy.mockRestore()

  expect(res.status).toBe(200)
})
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pnpm test -- --reporter=verbose 2>&1 | tail -20`
Expected: PASS — the Infinity path was already implemented in Task 2

- [ ] **Step 3: Commit**

```bash
git add src/index.test.ts
git commit -m "test: verify maxResponseSize: Infinity disables the limit"
```

---

### Task 4: Test ResponseExceededMaxSizeError re-export

**Files:**

- Test: `src/index.test.ts`

- [ ] **Step 1: Write the test for the re-export**

Update the import at the top of `src/index.test.ts` to include `ResponseExceededMaxSizeError`:

```ts
import {
  DEFAULT_MAX_RESPONSE_SIZE,
  ResponseExceededMaxSizeError,
  SsrfError,
  createSsrfSafeAgent,
  serverFetch,
  validateUrl,
} from './index'
```

Add a new describe block:

```ts
describe('ResponseExceededMaxSizeError', () => {
  it('is re-exported from undici', () => {
    expect(ResponseExceededMaxSizeError).toBeDefined()
    expect(ResponseExceededMaxSizeError.name).toBe('ResponseExceededMaxSizeError')
  })
})
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pnpm test -- --reporter=verbose 2>&1 | tail -20`
Expected: PASS — the re-export was already added in Task 1

- [ ] **Step 3: Commit**

```bash
git add src/index.test.ts
git commit -m "test: verify ResponseExceededMaxSizeError re-export from undici"
```

---

### Task 5: Run full test suite and lint

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `pnpm test`
Expected: All tests pass

- [ ] **Step 2: Run lint**

Run: `pnpm lint`
Expected: No errors

- [ ] **Step 3: Run format check**

Run: `pnpm fmt:check`
Expected: No formatting issues

- [ ] **Step 4: Run build**

Run: `pnpm build`
Expected: Build succeeds with no errors
