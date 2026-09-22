# Threat model (v0.6.0)

TRUSTED: gateway, KeyProvider, route registry, SQLite tx layer, executor code, server-side Route.network_policy, the api_keys table.
UNTRUSTED: agent, agent JSON, network, unsigned human input, upstream bodies, DNS answers.
ASSETS: grants, approvals, enforcer key, budgets, receipts, audit.

Budget windows are bound at authorization. Execution must not move spend onto a later UTC day.

DNS resolution is checked before connect. HTTP pins the checked IP. HTTPS still uses the hostname for SNI, so a resolver that changes answers between check and connect is a residual risk.

## Execution-time revalidation

Before claiming a new execution, the engine verifies the stored intent and
current principal-signed grant, checks the execution columns against the signed
intent, and reevaluates grant status, validity, scope, audience, counterparty and
limits in the same SQLite transaction as the execution claim. Budget evaluation
uses the original reservation day and excludes this receipt's own reservation.
A policy denial creates a signed DENIED result and releases that reservation.
Legacy authorizations without a budget binding fail closed and require a new
intent. Previously claimed executions remain single-use.

The execution claim is the ordering boundary: revocations committed before the
claim prevent dispatch. A revocation after the claim cannot cancel an in-flight
HTTP operation. This change does not provide exact request-byte binding, transport
hardening, crash reconciliation, or immutable evidence; those remain follow-ups.

## Money

Amounts are integer minor units everywhere past validation. A float cannot
represent 0.10 or 0.20, so summing them and comparing against a 0.30 cap
decided wrongly in 0.2.1. Conversion happens once, at the validation boundary,
from the same decimal text the agent's signature covers, and an amount finer
than the currency is refused rather than rounded. The ledger refuses a
non-integer amount outright, so no rounding can enter a budget by accident.

## Crash between claim and result

The execution claim is committed as a signed receipt whose outcome is
EXECUTING, so a reader never sees AUTHORIZED for a request that was already
dispatched. If this process dies before the result transaction, the receipt
stays EXECUTING until `reconcile_stale_executions()` moves it to
EXECUTION_UNKNOWN; the gateway runs that at startup. Whether the upstream saw
the request is unknowable from here, so the reservation is kept and freeing it
stays a human decision. An exception out of the executor is treated the same
way. Neither path re-dispatches: the execution claim remains single-use.

## Request composition

The agent signs an intent; it never composes the bytes that leave the gateway.
An Operation on the route names the method, the path, which intent fields and
which `context` keys may appear in the body. Values come from the signed
intent, names come from the server-side configuration, and only scalars cross
the boundary, so an agent cannot smuggle a shape or a destination the operation
never declared. An operation cannot widen its route's method or path allowlist.

The body is hashed and the hash is signed into the receipt before the request
is sent, and the executor sends exactly those bytes. This binds what the
gateway committed to sending. It is not proof that the upstream received them:
only the response hash speaks to that, and a timeout still yields
EXECUTION_UNKNOWN.

## Callers and tenants

An Ed25519 signature says who authored a grant or an intent. It says nothing
about who may reach the gateway, so the transport is authenticated separately
with an API key. The key names a tenant, and the tenant scopes every lookup:
grants, agents, receipts, nonces and routes. A record belonging to another
tenant is reported as absent, never as forbidden, so holding a valid key
elsewhere cannot confirm that an id exists.

Only the SHA-256 of the key secret is stored. That is sufficient because the
secret is 256 bits from a CSPRNG: there is no dictionary to attack, so a
password-hashing cost per request would buy nothing. A stolen key is contained
by disabling it, by its expiry, or by rotating it; it cannot be recovered from
the ledger.

The rate limiter is in-process. It bounds one gateway process, which is the
same scope as the single-file SQLite ledger it protects. Running several
gateway processes against one ledger would need a shared limiter, and is not
supported today.

## The MCP guard

The guard is a local process that speaks MCP to the model on one side and to an
upstream MCP server on the other. It signs intents on the agent's behalf,
because a model cannot sign. The enforcement boundary is therefore the guard
process: anything able to run code inside it can make it sign, and the grant's
limits are what stand between it and the upstream.

Tool arguments are untrusted. They never become named fields of a signed
intent — an MCP tool may take a `url` or a `host`, key names the validator
forbids — but travel as one canonical document whose hash the receipt binds
before dispatch. Only tools the configuration mapped are exposed, so the model
cannot reach a tool nobody classified.

Unlike the HTTP gateway there is no API key and no tenant check on the way in.
The caller is the local process that spawned the guard, not a remote client.

## Signing keys

A signer is what can produce a signature, which is not the same thing as what
holds the key. `agent_signer` and `enforcer_signer` name a kind: `aws-kms`,
`gcp-kms`, `vault-transit` and `command` keep the key outside this process,
which signs by asking rather than by reading. `kind: file` is also accepted and
loads a private key into the process — the default behaviour, named explicitly.
Everything below describes the first group.

This does not stop an attacker who already runs code in the process: they can
ask for signatures too, for as long as they are there, and the grant's limits
— not the key's location — are what bound what those signatures can do. What
it removes is the durable secret. There is nothing to exfiltrate, and signing
stops when access is revoked rather than continuing wherever the file was
copied. Whether a signature also leaves an audit record the host cannot edit
depends on the provider and how it is configured: AWS KMS, Cloud KMS and Vault
log signing operations; a `command` signer logs whatever the command it fronts
logs, which may be nothing.

Every remote signature is verified against the signer's DID before it is
returned, so a key manager holding a different key, or returning a DER-wrapped
or truncated signature, fails at sign time instead of producing a receipt that
will not verify later. A signer that cannot sign refuses the call outright:
`SIGNER_UNAVAILABLE`, nothing dispatched. The key manager's error text reaches
the operator's log, not the model, because a refusal is tool output and a
signing error can name hosts and paths.

The principal key is still local by default. Issuing and revoking grants is an
operator action, so the private key that does it does not belong to a serving
process at all — put it in a key manager too, or keep it off the host entirely.
