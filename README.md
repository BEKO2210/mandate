# Mandate v0.3.0

Enforcement gateway for AI-agent grants.

An agent cannot call a protected upstream unless the gateway has a currently valid principal authorization.

## What v0.3.0 adds

- **Operations.** A route declares, per signed action, which method, path and body fields may leave the gateway. The agent chooses values, never names, and never a destination.
- **Request binding.** The enforcer builds the body, hashes it, and signs that hash into the receipt *before* the request is sent. A receipt states what was sent, not merely what was authorized.
- Selected `context` keys can be forwarded, scalars only, each declared by the operation. A declared field is required; an undeclared one never travels.
- The executor sends exactly the hashed bytes, so the receipt hash and the wire bytes cannot drift apart.
- `allowed_methods` / `allowed_paths` are authoritative again: an operation cannot widen them, and a bad route configuration raises at construction.

```python
Route(
    audience="mandate://procurement",
    base_url="https://api.example.com",
    allowed_methods=("POST",),
    allowed_paths=("/orders",),
    operations=(
        Operation(
            action="purchase.office",
            method="POST",
            path="/orders",
            fields=("action", "amount_minor", "currency", "execution_id"),
            context_fields=("sku",),
        ),
    ),
)
```

A route with no declared operations keeps the pre-0.3 body and dispatches to the first registered method and path.

## What v0.2.2 established

- Exact money: amounts are integer minor units end to end, never floats
- Amounts finer than the currency (0.001 EUR, 0.5 JPY) are refused, not rounded
- The execution claim is signed as `EXECUTING`, so a stored receipt never reports `AUTHORIZED` for a request that was already dispatched
- An executor that raises ends as `EXECUTION_UNKNOWN` instead of leaving the receipt stuck
- `Engine.reconcile_stale_executions()` closes out claims whose process died; the gateway runs it at startup

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

Transport authentication, multi-tenancy, rate limiting and a tamper-evident receipt chain are not implemented. The gateway trusts everything that can reach it to be a legitimate caller of signed objects. Routes are configured in code, not from a file or an admin API.

## Known limitations

HTTPS DNS TOCTOU remains: hostname resolution is reused for SNI and certificate validation. The TLS peer IP is not pinned.

The receipt binds the request body the gateway *committed to sending*. It does not prove the upstream received those bytes; only the response hash speaks to that.

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
