# Mandate v0.2.2

Enforcement gateway for AI-agent grants.

An agent cannot call a protected upstream unless the gateway has a currently valid principal authorization.

## What v0.2.2 adds

- Exact money: amounts are integer minor units end to end, never floats
- Amounts finer than the currency (0.001 EUR, 0.5 JPY) are refused, not rounded
- The execution claim is signed as `EXECUTING`, so a stored receipt never reports `AUTHORIZED` for a request that was already dispatched
- An executor that raises ends as `EXECUTION_UNKNOWN` instead of leaving the receipt stuck
- `Engine.reconcile_stale_executions()` closes out claims whose process died; the gateway runs it at startup
- Test workflow in CI, Apache-2.0 LICENSE, security policy

## What v0.2.1 established

- Persistent enforcer identity via KeyProvider (keys outside the object store)
- SQLite ledger with atomic nonce consume and budget reservation
- Stable budget-day binding: spend uses the authorization day, not the execution clock
- Default-public destination policy; private networks require server-side opt-in
- Pre-buffer request body limit at the ASGI boundary (single 413)
- State machine with revalidating human approval
- Approval never jumps to EXECUTED
- Server-side route registry — no client target URL
- Redirects are not followed
- Enforcer-signed execution receipts

## What this does not do

MCP, A2A, EUDI, wallets, UI, subdelegation, organization credentials, marketplace, payments, perfect exactly-once HTTP.

Only the first registered method and path of a route are dispatched, and the intent's `context` is not forwarded, so real upstream payloads are not supported yet.

Transport authentication, multi-tenancy, rate limiting and a tamper-evident receipt chain are not implemented. The gateway trusts everything that can reach it to be a legitimate caller of signed objects.

## Known limitations

HTTPS DNS TOCTOU remains: hostname resolution is reused for SNI and certificate validation. The TLS peer IP is not pinned.

On timeout or an unknown executor error the state is `EXECUTION_UNKNOWN` and the reservation is kept. Reconciling it is a human decision; the gateway will not silently free the budget.

## Money

Wire format stays decimal (`"amount": 12.30`). Everything past validation is an
integer in minor units, so `0.10 + 0.20` is exactly `0.30` against a `0.30` cap.
An intent may also declare `"amount_minor": 1230`; if it does, it must agree.

## Run

```bash
python3 -m pytest tests/ -q
```

Gateway: GET /health, POST /v1/intents, POST /v1/approvals, GET /v1/receipts/{id}
