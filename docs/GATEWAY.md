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

Every endpoint but `/health` requires `Authorization: Bearer mk_<id>_<secret>`.
The key names a tenant and carries scopes: `intents:write`, `approvals:write`,
`receipts:read`, or `*`. A missing or invalid key is 401, a valid key without
the scope is 403, and a key over its rate limit is 429 with `Retry-After`.
A receipt belonging to another tenant answers 404.

Issue keys with `mandate keys new --tenant acme --name ci`; the token is
printed once. `mandate keys list` and `mandate keys disable --id <id>` manage
them afterwards.

`create_app()` requires an authenticator. For single-tenant development pass
`auth=OpenAccess()` explicitly.

    GET /v1/info -> enforcer DID, version and the calling tenant

Routes declare operations per signed action. The agent supplies values; the
server supplies method, path and field names. The request body is hashed and
signed into the receipt before it is sent.

The same engine can sit in front of an MCP server instead of an HTTP upstream;
the tool call replaces the request and the receipts are identical. See
`docs/MCP.md`.
