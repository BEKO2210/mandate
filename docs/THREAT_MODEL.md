# Threat model (v0.2.1)

TRUSTED: gateway, KeyProvider, route registry, SQLite tx layer, executor code, server-side Route.network_policy.
UNTRUSTED: agent, agent JSON, network, unsigned human input, upstream bodies, DNS answers.
ASSETS: grants, approvals, enforcer key, budgets, receipts, audit.

Budget windows are bound at authorization. Execution must not move spend onto a later UTC day.

DNS resolution is checked before connect. HTTP pins the checked IP. HTTPS still uses the hostname for SNI, so a resolver that changes answers between check and connect is a residual risk.
