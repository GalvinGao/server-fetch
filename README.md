# `server-fetch`

Safer `fetch` for server-side usages.

This library is designed to be having a strict-by-default policy of fetching resources on the server-side. It currently will:
- Enforce a 10s timeout by default.
- Deny all requests with a hostname that resolves/resolves to a IP address to a private network IP address, a AWS IMDS endpoint, or a local network IP address.
- Only allows URLs with the following rules:
  - `http` or `https` scheme.
  - Hostname is compliant with the public suffix list.
  - Port is either 80 or 443.

## TODOs

- [ ] Connect to the exact IP parsed/resolved from the hostname, instead of using the original form directly to mitigate spoofing.