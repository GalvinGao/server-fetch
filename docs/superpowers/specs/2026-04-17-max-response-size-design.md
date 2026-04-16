# Max Response Size

Configurable maximum response body size for `serverFetch()` to prevent memory exhaustion from large responses (GalvinGao/server-fetch#1).

## API Surface

Add `maxResponseSize` to `ServerFetchOptions`:

```ts
export interface ServerFetchOptions extends RequestInit {
  timeout?: number
  maxResponseSize?: number // bytes; default 10MB, Infinity to disable
}
```

- **Default:** `10 * 1024 * 1024` (10MB)
- **Disable:** pass `Infinity`

Export new constant `DEFAULT_MAX_RESPONSE_SIZE` for consumers that want to reference the default.

## Enforcement Strategy

Two layers, leveraging undici's built-in `maxResponseSize` on `Agent`:

### Layer 1: Content-Length pre-check

After `fetch()` resolves (headers received), check the `Content-Length` header. If it exceeds the limit, abort the response body and throw `SsrfError('RESPONSE_TOO_LARGE', ...)`.

This covers the common case (most servers send `Content-Length`) and gives an immediate, consistent error from `serverFetch()` itself.

### Layer 2: Undici Agent enforcement

Set `maxResponseSize` on the undici `Agent` dispatcher. Undici enforces the limit per-chunk during HTTP body parsing. This catches chunked/streaming responses where `Content-Length` is absent or lies.

Undici throws `ResponseExceededMaxSizeError` (code: `UND_ERR_RES_EXCEEDED_MAX_SIZE`) during body consumption (`.text()`, `.json()`, `.body.getReader()`, etc.).

### Why two layers

`fetch()` resolves when headers arrive — the body is lazy. Without the Content-Length pre-check, the user gets a Response object back and only discovers it's too large when reading the body. The pre-check gives immediate rejection for the majority of responses.

### Error type differences

| Scenario                     | Error type                                 | Thrown by                                     |
| ---------------------------- | ------------------------------------------ | --------------------------------------------- |
| Content-Length exceeds limit | `SsrfError` (code: `RESPONSE_TOO_LARGE`)   | `serverFetch()`                               |
| Chunked body exceeds limit   | `ResponseExceededMaxSizeError` from undici | Body consumption (`.text()`, `.json()`, etc.) |

Re-export `ResponseExceededMaxSizeError` from undici so consumers can catch it without importing undici directly.

## Agent Management

- Module-level `ssrfSafeAgent` gets `maxResponseSize: DEFAULT_MAX_RESPONSE_SIZE` (10MB).
- When `options.maxResponseSize` differs from the default, `serverFetch` creates a per-request `Agent` with the custom value and the SSRF-safe DNS lookup. `Infinity` is translated to `-1` (undici's "no limit" sentinel).
- Per-request agents are garbage collected after the response is consumed — no explicit cleanup needed.

## Error Model

Add `RESPONSE_TOO_LARGE` to the set of `SsrfError` codes. No changes to the `SsrfError` class itself — `code` is already `string`.

## `createSsrfSafeAgent`

No changes needed. `Agent.Options` already includes `maxResponseSize` via inheritance chain (`Agent.Options` > `Pool.Options` > `Client.Options`). Users can already pass `createSsrfSafeAgent({ maxResponseSize: ... })`.

## Testing

- `serverFetch` with default limit rejects responses with `Content-Length` > 10MB
- `serverFetch` with custom `maxResponseSize` respects the custom value
- `serverFetch` with `maxResponseSize: Infinity` disables the limit
- Content-Length pre-check throws `SsrfError` with code `RESPONSE_TOO_LARGE`
- Chunked responses exceeding the limit throw `ResponseExceededMaxSizeError` during body read
- `createSsrfSafeAgent({ maxResponseSize: ... })` passes the option through to undici
