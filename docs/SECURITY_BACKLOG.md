# Security hardening backlog after v0.2

This file tracks narrowly scoped follow-ups discovered during independent review of the remotely reproducible v0.2 Golden tree.

## SH-01 — Budget reservation day must be stable — DONE in v0.2.1

Authorization now records a `budget_bindings` row (receipt_id, grant_id, currency, day, amount) at reserve time. Commit, release, and EXECUTION_UNKNOWN handling use that bound day. Engine clock is injectable for tests; production uses UTC `utcnow()`.

Covered by G41–G44.

## SH-02 — Route destination resolution policy — DONE in v0.2.1

`Route.network_policy` defaults to `"public"`. Loopback/RFC1918 require explicit server-side `"allow_private"`. Metadata hosts and link-local addresses stay blocked even under `allow_private`. Hostnames are resolved with `getaddrinfo`; any blocked address fails closed.

HTTP connections pin the first allowed IP and send the original Host header. HTTPS keeps the hostname for SNI/certificate checks and therefore retains a DNS TOCTOU residual between check and connect.

Covered by G45–G52.

## SH-03 — Request body limit before buffering — DONE in v0.2.1

`BodyLimitMiddleware` rejects `Content-Length > MAX_BODY` without reading the body. Chunked/missing-length bodies are counted as they arrive and abort at `MAX_BODY + 1`.

Covered by G53–G57.

## Residual / next

- HTTPS DNS TOCTOU (check then connect by name)
- No connection-level IP pin for TLS
- IPv4-mapped addresses are unwrapped before policy checks
- Do not add MCP, A2A, EUDI, subdelegation, UI, marketplace, or payment-network work in this hardening round
