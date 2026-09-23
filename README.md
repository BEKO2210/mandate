# Mandate v0.9.0

Enforcement gateway for AI-agent grants.

An agent cannot call a protected upstream unless the gateway has a currently valid principal authorization — and cannot reach the gateway at all without a key.

## Install

```bash
pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"
mandate demo shop   # an agent buying through the MCP guard: limits, a denial, a human approval
```

Mandate is not on PyPI yet. The PyPI project named `mandate` is an unrelated
package, so install from the repository — or from a checkout with
`pip install -e ".[mcp]"`.

What a decision costs, and where the ceiling is: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

Or as a container — non-root, configuration and ledger in one volume:
`docker build -t mandate .`, then see [docs/DOCKER.md](docs/DOCKER.md).

## What v0.9.0 adds

The gaps the last releases listed as open, closed — each reproduced first,
each pinned by gates that fail against the code before it.

**Run it from one file.** The gateway used to be assembled in Python. Now:

```bash
mandate gateway check --config gateway.json   # validates, proves the signer signs
mandate gateway serve --config gateway.json --workers 4
```

Routes, operations, enforcer signer, auth, rate limit, CA bundle and
anchoring live in one JSON file, read strictly: an unknown key, a duplicate
key or a wrong type is an error with its location. The MCP guard's file is
now just as strict — a misspelt `max_daily_amount` used to be dropped and the
grant issued with no daily limit. `principal_signer` keeps the grant-issuing
key in a key manager. See `docs/GATEWAY.md`.

**The destination policy holds at the socket.** HTTPS connected by name, so
the name was resolved twice; a resolver that changed its answer sent an
authorized request to an internal address, and TLS did not stop it. Both
schemes now connect to the address that was checked. `HTTPS_PROXY` is ignored
— a proxy resolves the name itself. A `base_url` path prefix (`…/v2`) was
dropped on the way out; it is not any more.

**One rate limit across workers.** The bucket lives in the ledger, so N
workers no longer give a key N times its limit. Writing that exposed a ledger
hang: a transaction that failed to begin kept its lock forever.

**Unknown outcomes can be settled on the record.**

```bash
mandate gateway unknown --config gateway.json
mandate gateway resolve --config gateway.json --receipt rcpt_… \
    --outcome failed --by "Belkis" --reason "no order with this key in the ERP"
```

The finding is signed and chained into the receipt; the reservation is
committed or released. Until now the only way out of `EXECUTION_UNKNOWN` was
editing the database.

**Nothing is sent whose outcome cannot be signed.** With the enforcer on AWS
KMS (4096-byte cap), a verbose upstream error could push the result receipt
past the cap *after* the call: the outcome was lost. Error text is bounded,
and an execution whose receipt could outgrow the signer is refused before
dispatch.

**Heads go to a witness.** `mandate chain anchor --witness URL`, or the
gateway's `anchoring` block on a schedule. A witness that does not accept is
a failure, never a silence.

**Smaller things that were wrong:** nonces were kept forever (now pruned once
their intent is stale — and an intent must carry `created_at`, which used to
default to "now" and so was fresh forever); `/v1/info` reported version 0.5.0;
the whole repo is lint-clean, with ruff pinned in CI.

## What v0.8.0 adds

The three risks the last releases carried as documented residuals. One was
solvable; the other two are properties rather than bugs — a prefix of a valid
chain is a valid chain, and a stolen key signs whatever it likes — so they get
a mechanism that bounds them instead of a paragraph that admits them.

**Anchors, because nothing inside a database can speak for what was cut off
its end.**

```bash
$ mandate chain anchor --db .mandate/mandate.sqlite --file /mnt/witness/anchors.jsonl
default: seq 12 sha256:f4c5847b…

# later, after the last entries and their receipts quietly disappear
$ mandate chain verify --db … --anchors /mnt/witness/anchors.jsonl
tenant default: TAMPERED — an anchor recorded seq 12 for this tenant, and
                the chain no longer reaches it
$ echo $?
1
```

Without it the same database reports `9 entries intact` and exits 0. An anchor
stored on the same disk under the same operator buys nothing; where it goes is
the deployment's decision, and now the tool at least writes it.

**Key rotation, signed by the key being replaced.** A chain used to be pinned
to one key for life — rotating broke verification, so the practical advice was
never to, which makes one compromise unbounded in time.

```bash
mandate chain rotate --db … --config guard.toml --to did:key:z6Mku1qK…
```

A thief holding the current key cannot appoint themselves, and cannot rewrite
anything from before the rotation that handed them nothing.

**The road, not just the destination.** Verification checks that the states a
receipt passed through are a sequence the state machine allows, so a history
that skips authorization or runs backwards is a finding even when signed.

## What v0.7.0 established

**History that cannot be edited without showing it.** Every receipt state
appends an enforcer-signed entry to a per-tenant hash chain, and verification
walks the chain *and* reconciles it against the receipts it commits to — then
asks every receipt for its own proof.

```bash
$ mandate chain verify --db .mandate/mandate.sqlite
tenant default: TAMPERED — receipt rcpt_1c58a954… is in the chain at seq 13
                but no longer in the database
$ echo $?
1
```

Deleting a row, rolling a state back, editing a body, inserting a receipt or
fabricating one outright are all caught. Verification needs **no key and no
running gateway**, because the person who most needs to check a chain is the
one who does not trust whoever runs it. See [docs/CHAIN.md](docs/CHAIN.md).

## What v0.6.0 established

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
from asking for signatures. It removes the exfiltratable secret and makes
revocation effective; whether it also leaves an audit trail depends on the
provider. See [docs/KMS.md](docs/KMS.md).

## What v0.5.0 established

**Mandate in front of MCP tools.** The guard sits between a model and an
existing MCP server, re-exposes that server's tools with their own schemas, and
turns every call into a signed intent evaluated against a grant. Nothing on the
model's side changes — same tool names, same arguments, one refusal it has to
respect.

```bash
pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"
mandate mcp init  --config guard.json
mandate mcp serve --config guard.json
```

Install from the repository. The PyPI project named `mandate` is an unrelated
package: installing by that name gets someone else's code, not this.

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
- **Rate limiting.** A per-key token bucket, answering 429 with `Retry-After`. The bucket lives in the ledger, so every worker serving one ledger shares it.
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

- Guess intent. Every decision is deterministic policy over signed fields —
  scopes, amounts, budgets, counterparties, audience. What an agent *meant* is
  bounded by how narrowly the grant is written, and by human approval above a
  threshold, not by a model's reading of it.
- Move money. Mandate authorizes a call to a payment or ordering API; it is not
  one.
- Speak MCP over HTTP or SSE. The guard uses stdio on both sides.
- A2A, EUDI, wallets, a UI, subdelegation, organization credentials, a
  marketplace, or perfect exactly-once HTTP.

An admin API for routes and keys is not implemented; configuration is a file
and keys are managed with `mandate keys`.

## Known limitations

The receipt binds the request body the gateway *committed to sending*. It does not prove the upstream received those bytes; only the response hash speaks to that.

On timeout or an unknown executor error the state is `EXECUTION_UNKNOWN` and the reservation is kept. Settling it is a human decision, recorded with `mandate gateway resolve` — signed, chained, with who decided and why.

A key manager does not bound a live compromise: code inside the signing process can ask it for signatures for as long as it is there. Without `principal_signer`, the key that issues grants is a local development file.

The receipt chain makes edited history detectable, not impossible. Truncation from the end of a chain is invisible unless a head was kept elsewhere, and a compromised enforcer key can re-sign receipts and chain together.

## Money

Wire format stays decimal (`"amount": 12.30`). Everything past validation is an
integer in minor units, so `0.10 + 0.20` is exactly `0.30` against a `0.30` cap.
An intent may also declare `"amount_minor": 1230`; if it does, it must agree.

## Run

```bash
python3 -m pytest tests/ -q
mandate gateway check --config gateway.json
mandate gateway serve --config gateway.json --workers 4
```

Gateway: GET /health, GET /v1/info, POST /v1/intents, POST /v1/approvals, GET /v1/receipts/{id}

MCP guard: `mandate mcp serve --config guard.json`

Signer check: `mandate signer check --config guard.json`

Chain: `mandate chain verify --db .mandate/mandate.sqlite` · `mandate chain head --db …`
