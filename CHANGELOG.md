# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] — 2026-09-22

### Fixed

A third review round, on the code that fixed the second round's finding. Two
more ways to crash the verifier, both the same shape as the one before them
and both reproduced against a live database: an empty report, and a second,
ordinary tampering in the same database that went unreported because of it.

- **A proof that is not an object crashed the verifier.** `proof.get(...)` on
  a list raises `AttributeError`, which is neither `ValueError` nor
  `TypeError` and so escaped the error boundary. It did the same to
  `mandate verify` on a file — a traceback where `INVALID` belonged.
  `verify_object` now answers `False` for anything malformed instead of
  raising; every field it reads is hostile input by definition. Gate G186.
- **A deeply nested body crashed the verifier.** `RecursionError` escaped the
  boundary the same way. Gates G187, G188 — the first pins the behaviour for a
  body no interpreter can parse, the second checks that a body one *can* parse
  is still reconciled, because how deep is too deep is an interpreter detail
  (3.11 gives up at 1000, 3.13 reads 20000) and a gate written around one
  version's limit is a hole on another's.
- **The boundary now catches every exception, not a list of them.** Naming the
  expected ones encodes a guess about what hostile bytes can do, and that
  guess has been wrong three times running: `UnicodeEncodeError`,
  `AttributeError`, `RecursionError`. Failing there is conservative — the row
  becomes a finding and the run continues — so breadth costs nothing and
  narrowness costs the whole report.

Gates G186-G188. Full suite: 209 passed on Python 3.11 and 3.13.

## [0.7.0] — 2026-09-22

### Added

- **A tamper-evident receipt chain.** Every state a receipt reaches appends an
  enforcer-signed entry to a per-tenant hash chain, committing to the entry
  before it. Editing or removing an entry breaks every entry after it.
  Gates G158-G164.
- **Verification reconciles the chain against the receipts it commits to** —
  existence, state and a canonical hash of the stored body. This is the half
  that catches a deleted or altered row; the first implementation had only the
  self-check and caught nothing, which was found by deleting a row rather than
  by reading the code. Gates G165-G168.
- `mandate chain verify` and `mandate chain head`. Verification reads the
  database directly and needs **no key and no running gateway**: the person who
  most needs to check a chain is the one who does not trust whoever runs it.
  An early version required the enforcer key and reported every healthy chain
  as broken when run by anyone else. Gate G174.
- Gate G176 covers the composite attack the count check invites: removing one
  receipt and inserting another to keep the total level, in each of the four
  places it could be attempted.
- `/v1/info` returns the chain head for the caller's tenant, so the people the
  receipts are about can keep one. A head held outside the deployment is the
  only thing that makes truncation detectable. Gate G169.
- `Engine.verify_chain()`, `Engine.chain_head()` and a dependency-free
  `mandate.chain` module.

### Changed

- **A receipt cannot be written without a chain entry.** `insert_receipt`
  requires one and `cas_state` refuses without one, so the gap this closes
  cannot be reopened by forgetting an argument. Gates G170, G171.
- Ledger schema version 4. The chain starts empty and records how many receipts
  each tenant already had; seeding it from existing receipts would produce a
  chain that looks like it covered them all along. Those receipts are reported
  as a note, and a count above it as a finding. Gate G173.
- `submit_intent` converts a `SigningError` into a refusal instead of letting
  it escape past callers that handle `MandateError`. Pre-existing, and made
  likelier by the second signature this release adds. Gate G175.

### Fixed after independent review

- **The legacy baseline was an unsigned bypass.** It bounds how many unchained
  receipts are tolerated and lives in `meta`, where an operator can write:
  raising it by one licensed one forged receipt, with no key needed, defeating
  every count-based check. Genesis now binds it, so changing it breaks the
  chain at entry 1. The baseline is trusted on first use and immutable in
  effect from the first chained write. Gates G177, G178.
- **A duplicate JSON member was a free edit.** `json.loads` keeps the last of a
  repeated key, so prepending `"outcome": "DENIED"` changed the stored bytes
  while the canonical hash stayed put — and a parser that keeps the first would
  read a different receipt. Stored bodies are now parsed strictly. Gate G179.
- **Schema-4 migration was not atomic.** Two processes could both see version
  3; one could finish and write a chained receipt, and the other could count
  that receipt into the baseline, inflating the number that bounds unchained
  inserts. The snapshot and the version bump are one `BEGIN IMMEDIATE`
  transaction with the version re-checked under the write lock. Gate G180.
- **A tenant with no chain entries was never verified.** `mandate chain verify`
  took its list of tenants from the `chain` table, which skips exactly the
  shape a receipt written around the chain has: an operator could open a fresh
  tenant, insert a forged receipt into it, and the command walked every other
  tenant, found them intact and exited 0. Tenants are now the union of the
  chain and the receipts. Gate G181.
- **Nothing verified a stored receipt's own proof.** The chain establishes
  what the set of receipts is; it never asked whether a row in that set was
  ever signed. A fabricated receipt in a tenant whose chain was empty — and
  whose count an operator can licence by raising the baseline, the one window
  genesis cannot close — stood unexamined and the verifier exited 0.
  Reconciliation now verifies every receipt's proof against the key that proof
  names, chained or not, which needs no secret. Gates G182, G183.
- **One poisoned receipt silenced the whole verifier.** `"\ud800"` is a legal
  JSON escape and an illegal Unicode string: it parsed, then canonicalisation
  raised `UnicodeEncodeError` on the way out, past the error boundary. The run
  died with an empty report, so a single field hid every finding about every
  other receipt. Stored bodies are refused if they carry an unpaired surrogate
  or a non-JSON constant, and hashing and the proof check now sit inside the
  boundary: one poisoned row costs one finding, never the run. Gates G184,
  G185.

### Still open

A chain cannot prove what was removed from its own end: truncation is only
detectable against a head kept outside the deployment, and where that head goes
is a deployment decision. A compromised enforcer key allows receipts and chain
to be re-signed together. Chains are per tenant, so a whole tenant's history
can be dropped without another tenant's chain noticing. Route and key
configuration outside code, and nonce pruning, remain unimplemented.

## [0.6.0] — 2026-09-22

### Added

- **Signing keys that never enter the process.** A `Signer` is anything that
  can name a DID and sign bytes; `KeyPair` is one, and so is a key manager that
  will not hand the key back. `mandate/signing.py` adds AWS KMS
  (`ECC_NIST_EDWARDS25519`), Google Cloud KMS (`EC_SIGN_ED25519`), Vault's
  transit engine (`ed25519`) and an external command for HSMs and PKCS#11.
  Gates G120-G122, G129-G140.
- **Every remote signature is verified before it is returned.** A key manager
  pointed at the wrong key, or returning a DER-wrapped or truncated signature,
  fails at sign time rather than producing a receipt nobody can verify later.
  Gates G123-G125.
- `Signer.check()` and `mandate signer check --config` prove a signer works —
  and that it holds the DID the grant was issued to — before anything depends
  on it. The guard runs the same check at startup and refuses to serve if it
  fails. Gates G126-G128.
- `agent_signer` and `enforcer_signer` in an MCP guard configuration. With
  `agent_signer` set, `mandate mcp init` generates and writes no agent key at
  all. Secrets come from the environment, never from the configuration file, so
  the file can be committed. Gates G141-G142, G145-G148.
- `SignerKeyProvider` puts the gateway's enforcer key in a key manager.
  Receipts verify exactly as before. Gate G121.
- `Engine.register_principal(signer=…)` and `register_agent(signer=…)` record a
  DID a key manager already holds instead of generating a private key. Gate
  G122.

### Changed

- The MCP guard refuses a call it cannot sign — `SIGNER_UNAVAILABLE`, nothing
  dispatched. An unsigned intent must never reach an upstream. Gate G144.
- A signing failure's detail reaches the operator's log, not the model:
  refusal text is tool output, and a key manager's error can name hosts, paths
  and ARNs. `GuardDecision.detail` carries it. Gate G149.
- `McpGuard(agent_kp=…)` is now `McpGuard(agent_signer=…)`, and
  `load_agent_key` is `load_agent_signer`. Breaking, and only for callers that
  built a guard directly.
- Vault over plain `http` is refused unless chosen out loud: the token travels
  in a header. Gates G135-G137.
- `AwsKmsSigner` refuses a payload over 4096 bytes with a message naming the
  alternatives. Found by measuring rather than reading: an EXECUTED receipt is
  already ~2.9 KiB, and a 2031-byte context — legal under `MAX_CONTEXT_BYTES` —
  produces a 4115-byte receipt that KMS rejects. Signing a digest instead is
  not an escape, because `ED25519_PH_SHA_512` is HashEdDSA and would not verify
  against the object's own `did:key`. Gate G150.

### Fixed after independent review

- A malformed configured `did` escaped as `ValueError` (or `AttributeError` for
  a non-string) from inside `crypto.verify`, past every `SigningError` handler
  in the guard and the startup checks. DIDs are validated at construction.
  Gate G151.
- **The Vault token was forwarded to a redirect target.** `urllib` copies
  ordinary headers onto a redirected request — across origins, and across an
  https-to-http downgrade — so a 302 from a compromised or spoofed Vault handed
  `X-Vault-Token` to whoever the `Location` named. Reproduced against a live
  server; redirects are now surfaced, never followed. Gate G152.
- **A signing failure after dispatch was reported as a failed dispatch.**
  `Engine.execute()` caught only `StorageError` around both signatures. After
  `executor.forward()` the upstream may already have acted, so the new
  `ExecutionUnknown` keeps the receipt EXECUTING with its reservation held and
  tells the caller the outcome is unknown, never that nothing was sent. This
  also corrects the pre-existing case where a post-dispatch `StorageError`
  became `DISPATCH_FAILED`. Gates G153-G155.
- **A lost state race after dispatch was also reported as a failed dispatch.**
  If the reconciler moved a receipt out of `EXECUTING` while the upstream call
  was in flight, the final `cas_state` lost and raised
  `MandateError("invalid state transition")` — which the guard turned into
  `DISPATCH_FAILED` for a call that had already gone out. It now raises
  `ExecutionUnknown` like every other post-dispatch failure. Gate G157
  reproduces the race with a blocking executor rather than a mock.
- The guard proves the **enforcer** signer can sign before exposing any tool.
  `Engine` only asks it for its DID, which a remote signer can answer from a
  published public key while lacking permission to sign. Gate G156.
- Documentation no longer describes every configured signer as remote
  (`kind: file` is accepted and keeps the key in-process), nor promises an
  immutable signing log for providers that may not keep one.

### Still open

A key manager does not bound a live compromise of the signing process — code
running inside it can ask for signatures for as long as it is there. The
principal key that issues grants is local by default. The HTTP gateway still
takes its enforcer signer as a constructor argument, because routes and keys
are configured in code. A tamper-evident receipt chain and nonce pruning are
not implemented. AWS KMS cannot hold an enforcer key for deployments whose
receipts approach 4 KiB.

## [0.5.0] — 2026-09-22

### Added

- **MCP guard.** `mandate mcp serve` puts Mandate between a model and an
  existing MCP server: the upstream's tools are re-exposed with their own
  schemas, and every call becomes a signed intent evaluated against a grant
  before it is dispatched. The model's side does not change. Gates G112-G119.
- `mandate/mcp/mapping.py` decides, server-side, what each tool counts as and
  which argument carries money. An unmapped tool is not exposed at all, so the
  surface a model sees is the surface the configuration considered. Gates
  G101-G106, G115, G117.
- `McpExecutor` dispatches an authorized call over MCP with the same contract
  as the HTTP executor: a tool error is `EXECUTION_FAILED`, a broken transport
  is `EXECUTION_UNKNOWN` with the reservation kept. Gates G107-G111, G116.
- `mandate mcp init` creates the principal, agent and grant, scoping the grant
  to exactly the mapped actions. Gates G117, G118.
- Optional extra: `pip install "mandate[mcp]"`.

### Changed

- `ExecutionResult` can carry the upstream's response in-process. Only its hash
  is signed into the receipt; the content itself is handed to the caller beside
  the receipt and never persisted. Gate G112.
- `Operation.max_string` lets one operation raise the forwarded-string limit
  above the global default. The limit stays server-side, and the total body cap
  is unchanged.
- **`MAX_CONTEXT_BYTES` is enforced.** It was declared from the first release
  and never checked, so an intent's context was bounded only by the 32 KiB body
  limit. It is now validated against the canonical bytes that get signed.
  Gate G104.

### Still open

A KMS key provider, route configuration outside code, nonce pruning, a
tamper-evident receipt chain, and the HTTPS DNS TOCTOU residual. The guard
holds the agent key, so its process is the enforcement boundary — see
`docs/MCP.md`.

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
