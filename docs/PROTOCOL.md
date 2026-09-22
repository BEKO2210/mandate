# Mandate Protocol 0.2

Signed objects exclude proof, canonicalize, Ed25519-sign.
Authorization is not execution. Approval cannot set EXECUTED.
Audience is signed. Upstream URL exists only in the server registry.

## Amounts (0.2.2)

Wire format is decimal: `"amount": 12.30` with `"currency": "EUR"`.
Everything past validation is an integer in minor units, derived from the
decimal text the signature covers. An amount finer than the currency's minor
unit is refused, never rounded. An intent may also carry `"amount_minor": 1230`;
when present it must agree with the decimal amount.

## Execution states

PROPOSED -> DENIED | HUMAN_REQUIRED | AUTHORIZED -> EXECUTING -> EXECUTED |
EXECUTION_FAILED | EXECUTION_UNKNOWN; EXECUTION_UNKNOWN -> EXECUTED |
EXECUTION_FAILED by an operator's resolution only.

EXECUTING is a claim, not a result: it is stored as a signed receipt so a
crashed dispatch is never reported as AUTHORIZED. Only EXECUTION_UNKNOWN keeps
its budget reservation, until someone who asked the upstream resolves it:
`EXECUTED` commits the reservation, `EXECUTION_FAILED` releases it. The
finding — who, why, when — is written into `execution.resolution`, and the
receipt is re-signed and chained like every other state.

## Operations and request binding (0.3.0)

The upstream URL, method and path exist only in the server-side registry. A
route declares an Operation per signed action:

    Operation(action, method, path, fields, context_fields)

`fields` is an allowlist over action, amount, amount_minor, currency,
counterparty, summary, intent_id and execution_id. `context_fields` forwards
named keys of the intent's `context`, scalars only, each required once
declared. Nothing else reaches the upstream.

The receipt carries, signed before dispatch:

    execution.request = {method, path, destination, hash, size}

where `hash` is `sha256:<hex>` over the exact bytes sent.

## Tenancy (0.4.0)

Every principal, agent, grant, receipt, nonce and route belongs to a tenant.
The API key presented on the request decides which tenant a call operates in;
it is never carried in a signed object, so a compromised agent key cannot move
authority between tenants. Nonce uniqueness is per (tenant, audience, nonce).
Records of another tenant are reported as absent rather than forbidden.
