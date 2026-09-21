# Gateway

Untrusted agent → Mandate Enforcement Gateway → trusted executor → registered route only.

POST /v1/intents { intent, execute }
POST /v1/approvals { approval, execute }
GET /v1/receipts/{id}
GET /health

Forbidden: target_url, destination_url, host, base_url, proxy_url, url, network_policy.

Body limit: 32768 bytes, enforced at ASGI receive before unbounded buffering.

Route destinations default to `network_policy=public`. Loopback/private targets require server-side `allow_private`. HTTPS destination checks resolve DNS before connect but do not pin the TLS peer IP (TOCTOU residual).

Startup runs `Engine.reconcile_stale_executions()`: receipts left in EXECUTING
by a process that died are closed as EXECUTION_UNKNOWN, keeping their
reservation.

The gateway has no transport authentication, no tenancy and no rate limiting.
Anything that can reach it may submit signed objects, and `/v1/receipts/{id}`
is readable by anyone holding an id. Terminate it behind an authenticating
proxy on a trusted network.
