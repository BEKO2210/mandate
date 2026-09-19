# Mandate v0.2

Enforcement gateway for AI-agent grants.

An agent cannot call a protected upstream unless the gateway has a currently valid principal authorization.

## What v0.2 does

- Persistent enforcer identity via KeyProvider (keys outside the object store)
- SQLite ledger with atomic nonce consume and budget reservation
- State machine with revalidating human approval
- Approval never jumps to EXECUTED
- Server-side route registry — no client target URL
- Redirects are not followed
- Enforcer-signed execution receipts

## What v0.2 does not do

MCP, A2A, EUDI, wallets, UI, subdelegation, organization credentials, marketplace, payments, perfect exactly-once HTTP.

On timeout the state is EXECUTION_UNKNOWN and the reservation is kept.

```bash
python3 -m pytest tests/ -q
```

Gateway: GET /health, POST /v1/intents, POST /v1/approvals, GET /v1/receipts/{id}
