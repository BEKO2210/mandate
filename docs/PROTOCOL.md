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
EXECUTION_FAILED | EXECUTION_UNKNOWN.

EXECUTING is a claim, not a result: it is stored as a signed receipt so a
crashed dispatch is never reported as AUTHORIZED. Only EXECUTION_UNKNOWN keeps
its budget reservation.
