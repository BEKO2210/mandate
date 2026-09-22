# Mandate v0.6.0

Enforcement gateway for AI-agent grants.

An agent cannot call a protected upstream unless the gateway has a currently valid principal authorization — and cannot reach the gateway at all without a key.

## What v0.6.0 adds

**The signing key no longer has to be in the process.** A signer is anything
that can name a DID and sign bytes — a local key, or AWS KMS, Cloud KMS, Vault
transit, or a command fronting an HSM. With one configured, `mandate mcp init`
generates and writes no agent key at all.

```json
"agent_signer": {"kind": "aws-kms", "key_id": "arn:aws:kms:eu-central-1:1234:key/abcd"}
```

```bash
$ mandate signer check --config guard.json
agent    : aws-kms ok, held elsewhere
           did:key:z6Mkkhyu…
```

Every remote signature is verified against the signer's DID before it is
returned, so a key manager holding the wrong key fails at sign time instead of
producing a receipt that will not verify. A signer that cannot sign refuses the
call — `SIGNER_UNAVAILABLE`, nothing dispatched.

What this does **not** do: stop code already running in the signing process
from asking for signatures. It removes the exfiltratable secret, makes
revocation effective, and leaves a signing log the host cannot edit. See
[docs/KMS.md](docs/KMS.md).

## What v0.5.0 established

**Mandate in front of MCP tools.** The guard sits between a model and an
existing MCP server, re-exposes that server's tools with their own schemas, and
turns every call into a signed intent evaluated against a grant. Nothing on the
model's side changes — same tool names, same arguments, one refusal it has to
respect.

```bash
pip install "mandate[mcp]"
mandate mcp init  --config guard.json
mandate mcp serve --config guard.json
```

```
create_issue        -> UPSTREAM RAN create_issue on beko/mandate     isError: False
pay_invoice 900 EUR -> Mandate denied this call: amount 900.00 exceeds
                       max_amount 100.00 … limit of grant grant_a34…  isError: True
delete_repository   -> not exposed: the configuration never mapped it
```

A tool that is not mapped is not exposed. A refusal names the rule, the grant
and the receipt, so the agent can act on it instead of retrying. See
[docs/MCP.md](docs/MCP.md).

## What v0.4.0 established

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

A tamper-evident receipt chain, route and key configuration outside code and CLI, and nonce pruning are not implemented.

## Known limitations

HTTPS DNS TOCTOU remains: hostname resolution is reused for SNI and certificate validation. The TLS peer IP is not pinned.

The receipt binds the request body the gateway *committed to sending*. It does not prove the upstream received those bytes; only the response hash speaks to that.

The rate limiter is in-process, so it bounds one gateway process. That matches a ledger that is a single SQLite file on one node.

On timeout or an unknown executor error the state is `EXECUTION_UNKNOWN` and the reservation is kept. Reconciling it is a human decision.

A key manager does not bound a live compromise: code inside the signing process can ask it for signatures for as long as it is there. The principal key that issues grants is local by default.

## Money

Wire format stays decimal (`"amount": 12.30`). Everything past validation is an
integer in minor units, so `0.10 + 0.20` is exactly `0.30` against a `0.30` cap.
An intent may also declare `"amount_minor": 1230`; if it does, it must agree.

## Run

```bash
python3 -m pytest tests/ -q
```

Gateway: GET /health, GET /v1/info, POST /v1/intents, POST /v1/approvals, GET /v1/receipts/{id}

MCP guard: `mandate mcp serve --config guard.json`

Signer check: `mandate signer check --config guard.json`
