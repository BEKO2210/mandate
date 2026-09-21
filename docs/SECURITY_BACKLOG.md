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

## SH-04 — Money must be exact — DONE in v0.2.2

Float amounts decided caps wrongly: 0.10 + 0.20 against a 0.30 daily cap was
denied, and ten 0.10 reservations against a 1.00 cap accumulated to
0.9999999999999999. Amounts, constraints and budgets are now integer minor
units (`mandate/money.py`), converted once at the validation boundary from the
same decimal text the signature covers. An amount finer than the currency is
refused rather than rounded into a budget. Ledger schema version 2 converts
legacy float rows half-up, once, on first open.

Covered by G58-G63 and G68.

## SH-05 — A claimed execution must reach a terminal state — DONE in v0.2.2

`AUTHORIZED -> EXECUTING` stored the previous signed body, so the ledger said
EXECUTING while the receipt said AUTHORIZED, and a retry returned that body for
a request that may already have been dispatched. The claim is now signed as
EXECUTING. Any exception out of the executor becomes EXECUTION_UNKNOWN with the
reservation kept, and `Engine.reconcile_stale_executions()` closes out claims
whose process died; the gateway runs it at startup.

Covered by G64-G67.

## SH-06 — The request body must be decided server-side and bound — DONE in v0.3.0

Until 0.2.2 only `allowed_methods[0]` and `allowed_paths[0]` were dispatched
with a fixed four-field body, so the gateway could not carry real work and the
receipt said nothing about the bytes that left it. A route now declares an
`Operation` per signed action: method, path, an allowlist of intent fields and
an allowlist of `context` keys. The enforcer builds the body, hashes it, and
signs that hash into the receipt before dispatch; the executor sends exactly
those bytes. Undeclared fields never travel, non-scalar or oversized values are
refused, and an operation cannot widen its route's method or path allowlist.

Covered by G70-G79.

## Residual / next

- HTTPS DNS TOCTOU (check then connect by name)
- No connection-level IP pin for TLS
- No transport authentication, multi-tenancy or rate limiting on the gateway
- Receipts are individually signed but not chained; an operator with database
  access can delete or roll back history
- The request hash binds what the gateway sent, not what the upstream received
- Routes and operations are configured in code, not from a file or admin API
- Reconciling an EXECUTION_UNKNOWN reservation is still a manual decision
