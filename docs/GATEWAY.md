# Gateway

Untrusted agent → Mandate Enforcement Gateway → trusted executor → registered route only.

POST /v1/intents { intent, execute }
POST /v1/approvals { approval, execute }
GET /v1/receipts/{id}
GET /health

Forbidden: target_url, destination_url, host, base_url, proxy_url, url, network_policy.

An approval is signed by the grant's principal and must carry `receipt_id`,
`intent_id` and `created_at`; it is accepted for ten minutes after
`created_at` and not after its optional `not_after`.

Body limit: 32768 bytes, enforced at ASGI receive before unbounded buffering.

Route destinations default to `network_policy=public`. Loopback/private targets require server-side `allow_private`. The name is resolved once and the connection goes to the address that was checked, for HTTPS as well; SNI and certificate verification still use the name. Proxy environment variables are ignored.

Startup runs `Engine.reconcile_stale_executions()`: receipts left in EXECUTING
by a process that died are closed as EXECUTION_UNKNOWN, keeping their
reservation.

`mandate gateway unknown --config gateway.json` lists those receipts with the
method, destination, idempotency key and request hash — what to ask the
upstream about. `mandate gateway resolve --config gateway.json --receipt …
--outcome executed|failed --by … --reason …` records the answer: signed,
chained, and settling the reservation.

Every endpoint but `/health` requires `Authorization: Bearer mk_<id>_<secret>`.
The key names a tenant and carries scopes: `intents:write`, `approvals:write`,
`receipts:read`, or `*`. A missing or invalid key is 401, a valid key without
the scope is 403, and a key over its rate limit is 429 with `Retry-After`.
The limit is kept in the ledger, so it holds across every worker serving it.
A receipt belonging to another tenant answers 404.

Issue keys with `mandate keys new --tenant acme --name ci`; the token is
printed once. `mandate keys list` and `mandate keys disable --id <id>` manage
them afterwards.

`create_app()` requires an authenticator. For single-tenant development pass
`auth=OpenAccess()` explicitly.

## Run from a configuration file

```json
{
  "store": "/var/lib/mandate",
  "enforcer_signer": {"kind": "vault-transit", "key": "mandate-enforcer"},
  "rate_limit": {"per_minute": 120, "burst": 20},
  "routes": [{
    "audience": "mandate://procurement",
    "base_url": "https://erp.example.com/api/v2",
    "allowed_methods": ["POST"],
    "allowed_paths": ["/orders"],
    "operations": [{
      "action": "purchase.office", "method": "POST", "path": "/orders",
      "fields": ["action", "amount", "currency", "execution_id"]
    }]
  }]
}
```

```
mandate gateway check --config gateway.json
mandate gateway serve --config gateway.json --port 8080 --workers 4
mandate keys new --db /var/lib/mandate/mandate.sqlite --tenant acme --name ci
```

`check` validates the file, proves the enforcer signer can sign and reports
where each key lives; it exits non-zero on anything it cannot vouch for. Run
it before `serve`, not after the first refused intent.

The file is read strictly: an unknown key at any level, a duplicate key, a
wrong type or an out-of-range value is an error that names its location. A
misspelt `enforcer_signer` that fell back to a generated local key would be a
configuration bug that *works*, which is the worst kind.

- `auth` defaults to API keys. `{"kind": "open", "tenant": "…"}` turns
  authentication off and is reported as such by `check`.
- `enforcer_signer` absent means a development key under `store`.
- `ca_bundle` names a CA file for upstreams behind a private CA. Certificate
  verification cannot be switched off.
- `base_url` may carry a path prefix; it may not carry credentials, a query or
  a fragment.
- `anchoring` posts every tenant's chain head to a witness on a schedule; see
  `docs/CHAIN.md`.
- Relative paths are relative to the configuration file.

Workers share the ledger, and with it the rate limit per key. Each worker
builds its app from the same file (`MANDATE_GATEWAY_CONFIG`, set by `serve`).

    GET /v1/info -> enforcer DID, version and the calling tenant

Routes declare operations per signed action. The agent supplies values; the
server supplies method, path and field names. The request body is hashed and
signed into the receipt before it is sent.

The same engine can sit in front of an MCP server instead of an HTTP upstream;
the tool call replaces the request and the receipts are identical. See
`docs/MCP.md`.
