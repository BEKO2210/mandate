# Threat model (v0.2.1)

TRUSTED: gateway, KeyProvider, route registry, SQLite tx layer, executor code, server-side Route.network_policy.
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
