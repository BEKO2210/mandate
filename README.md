# Mandate v0.4.0

Enforcement gateway for AI-agent grants.

An agent cannot call a protected upstream unless the gateway has a currently valid principal authorization — and cannot reach the gateway at all without a key.

## What v0.4.0 adds

- **Transport authentication.** Every endpoint but `/health` requires `Authorization: Bearer mk_<id>_<secret>`. Only the SHA-256 of the secret is stored, comparison is constant time, and an unknown key id takes the same path as a wrong secret.
- **Tenancy.** Principals, agents, grants, receipts, nonces and routes belong to a tenant; the key decides which one. Another tenant's record reads as *absent*, never as forbidden, so a valid key cannot be used to confirm that an id exists.
- **Rate limiting.** A per-key token bucket, answering 429 with `Retry-After`.
- `create_app()` refuses to build an unauthenticated gateway. That has to be chosen out loud with `auth=OpenAccess()`.

```bash
mandate keys new --tenant acme --name ci --scopes intents:write,receipts:read
# token is printed once and is not recoverable

curl -H "Authorization: Bearer mk_..." -X POST http://localhost:8000/v1/intents \
     -d '{"intent": {...}}'
```

Scopes: `intents:write`, `approvals:write`, `receipts:read`, or `*`.
401 = no or invalid key, 403 = valid key without the scope, 404 = not yours,
429 = over the limit.

Single-tenant deployments are unaffected: every engine method takes a `tenant`
that defaults to `"default"`.

## What v0.3.0 established

- Operations: a route declares, per signed action, the method, path and body fields that may leave the gateway
- Request binding: the body is hashed and the hash signed into the receipt *before* the request is sent

## What v0.2.2 established

- Exact money: amounts are integer minor units end to end, never floats
- The execution claim is signed as `EXECUTING`, so a stored receipt never reports `AUTHORIZED` for a request that was already dispatched
- `Engine.reconcile_stale_executions()` closes out claims whose process died

## What v0.2.1 established

- Persistent enforcer identity via KeyProvider (keys outside the object store)
- SQLite ledger with atomic nonce consume and budget reservation
- Stable budget-day binding: spend uses the authorization day, not the execution clock
- Default-public destination policy; private networks require server-side opt-in
- Pre-buffer request body limit at the ASGI boundary (single 413)
- State machine with revalidating human approval; approval never jumps to EXECUTED
- Server-side route registry — no client target URL; redirects are not followed
- Enforcer-signed execution receipts

## What this does not do

MCP, A2A, EUDI, wallets, UI, subdelegation, organization credentials, marketplace, payments, perfect exactly-once HTTP.

A tamper-evident receipt chain, a KMS key provider, route and key configuration outside code and CLI, and nonce pruning are not implemented.

## Known limitations

HTTPS DNS TOCTOU remains: hostname resolution is reused for SNI and certificate validation. The TLS peer IP is not pinned.

The receipt binds the request body the gateway *committed to sending*. It does not prove the upstream received those bytes; only the response hash speaks to that.

The rate limiter is in-process, so it bounds one gateway process. That matches a ledger that is a single SQLite file on one node.

On timeout or an unknown executor error the state is `EXECUTION_UNKNOWN` and the reservation is kept. Reconciling it is a human decision.

## Money

Wire format stays decimal (`"amount": 12.30`). Everything past validation is an
integer in minor units, so `0.10 + 0.20` is exactly `0.30` against a `0.30` cap.
An intent may also declare `"amount_minor": 1230`; if it does, it must agree.

## Run

```bash
python3 -m pytest tests/ -q
```

Gateway: GET /health, GET /v1/info, POST /v1/intents, POST /v1/approvals, GET /v1/receipts/{id}
