# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-09-21

### Added

- **Transport authentication.** Every endpoint but `/health` requires
  `Authorization: Bearer mk_<id>_<secret>`. Only the SHA-256 of the secret is
  stored, verification is constant time, and an unknown key id takes the same
  path as a wrong secret. Keys carry scopes, an optional expiry and a disable
  switch. Gates G86, G87, G88, G93.
- **Tenancy.** Principals, agents, grants, receipts, nonces and routes belong
  to a tenant, and the caller's key decides which one. A record of another
  tenant reads as absent, never as forbidden, so a valid key elsewhere cannot
  confirm that a grant or receipt exists. Nonces are keyed per tenant, so one
  tenant cannot burn another's. Gates G81-G85, G94, G98.
- **Rate limiting.** A per-key token bucket, answering 429 with `Retry-After`.
  Gates G91, G95.
- `mandate keys new|list|disable` to issue and revoke gateway keys. The token
  is printed once and is not recoverable.
- `GET /v1/info` carries the enforcer DID, version and tenant, behind
  authentication.

### Changed

- `create_app()` now requires an authenticator. Running unauthenticated has to
  be chosen out loud with `auth=OpenAccess()`. Gate G92.
- `/health` returns `{"ok": true}` only. It touches no storage and reveals no
  identity, so it cannot be used to amplify load or probe for keys.
- Engine methods take a `tenant` argument, defaulting to `"default"`, so
  single-tenant deployments behave exactly as before.
- `Route` gained a `tenant` field and `RouteRegistry.get()` resolves an
  audience within a tenant. Two tenants may reuse an audience name without
  ever reaching each other's upstream.
- Issuing a grant for an agent registered in another tenant fails. Gate G98.
- Ledger schema version 3 adds tenant columns and rebuilds the nonce table
  with the tenant in its primary key. Pre-0.4 rows join the `default` tenant.

### Still open

A KMS key provider, route configuration outside code, nonce pruning, a
tamper-evident receipt chain, and the HTTPS DNS TOCTOU residual. The rate
limiter is in-process, which bounds one gateway process; that matches a ledger
that is a single SQLite file on one node.

## [0.3.0] — 2026-09-21

### Added

- **Operations.** `Route.operations` declares, per signed action, the method,
  path and body fields that may leave the gateway. `Operation.fields` is an
  allowlist over known intent fields; `Operation.context_fields` forwards
  selected `context` keys, scalars only. The agent chooses values, never field
  names and never a destination. Gates G70, G77.
- **Request binding.** The enforcer builds the body, hashes it, and signs that
  hash into the receipt before the request is sent, as
  `execution.request = {method, path, destination, hash, size}`. A receipt now
  states what was sent, not merely what was authorized. Gates G71, G72.
- Route configuration is validated at construction: an operation cannot widen
  `allowed_methods` or `allowed_paths`, cannot name an unknown intent field,
  and two operations cannot claim the same action. Gate G76.

### Changed

- `UpstreamExecutor.forward()` takes the encoded body as `bytes` instead of a
  dict and sends exactly those bytes with an explicit `Content-Type`, so the
  hash in the receipt and the bytes on the wire cannot drift apart. This is a
  breaking change for custom executors.
- An authorized action with no matching operation on its route fails closed
  before the execution claim; nothing is dispatched and the receipt stays
  AUTHORIZED. Gate G75.
- A declared context field is required, a non-scalar or oversized value is
  refused, and an undeclared key never reaches the upstream. Gates G73, G74, G79.
- A route with no declared operations keeps the pre-0.3 body and first
  registered method and path. Gate G78.

### Still open in the 0.3 line

Transport authentication, multi-tenancy, rate limiting, a KMS key provider,
route configuration outside code, and nonce pruning.

## [0.2.2] — 2026-09-21

### Fixed

- **Money is exact.** Amounts, constraints and budgets are integer minor units
  end to end. `0.10 + 0.20` against a `0.30` daily cap was denied in 0.2.1
  because floats cannot represent those values; it is now authorized. Ten
  reservations of `0.10` against a `1.00` cap stored `0.9999999999999999`; they
  now store exactly `100` minor units. Gates G58, G59, G63.
- **A dispatched request is never reported as merely authorized.** The
  `AUTHORIZED -> EXECUTING` claim is written as a freshly signed body with
  `outcome: EXECUTING`. In 0.2.1 the claim stored the previous `AUTHORIZED`
  body, so the ledger state and the signed receipt disagreed and a retry handed
  back `AUTHORIZED` for a request that may already have reached the upstream.
  Gates G65, G67.
- **An executor that raises no longer strands the receipt.** Any exception out
  of `forward()` becomes `EXECUTION_UNKNOWN` with the reservation kept, instead
  of leaving the receipt in a non-terminal `EXECUTING` state whose budget was
  blocked forever. Gate G64.

### Added

- `mandate.money`: ISO 4217 minor-unit exponents, exact conversion, and refusal
  of amounts finer than the currency (`0.001` EUR, `0.5` JPY). Gates G60, G61.
- Optional `amount_minor` on an intent. When present it must agree with the
  decimal `amount`. Gate G62.
- `Engine.reconcile_stale_executions()` closes out claims whose process died,
  moving them to `EXECUTION_UNKNOWN` and keeping the reservation. The gateway
  runs it on startup. Gate G66.
- Ledger schema version 2: integer minor-unit budgets, `receipts.amount_minor`,
  `budget_bindings.amount_minor`, `executions.started_at`. Pre-0.2.2 float rows
  are converted once, rounded half-up, on first open. Gate G68.
- Test workflow in CI across Python 3.11-3.13, `LICENSE` (Apache-2.0),
  `SECURITY.md`, this changelog.

### Changed

- `Ledger` budget methods take and return integer minor units. `spent()` returns
  an `int`; `budget_snapshot()` returns exact `Decimal` major units and
  `budget_snapshot_minor()` returns integers.
- `policy.evaluate()` takes `spent_today_minor` instead of `spent_today`.
- A budget binding written before 0.2.2, without an exact amount, is treated as
  missing and fails closed.

## [0.2.1] — 2026-09-20

- Stable budget-day binding (SH-01)
- Route destination network policy, default public (SH-02)
- Request body limit before buffering (SH-03)
- Execution-time revalidation inside the execution claim
