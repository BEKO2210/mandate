# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `.github/workflows/release.yml`: a published GitHub release is built and
  proven installable — the tag must equal the pyproject version, the suite
  runs, `twine check --strict` passes, the wheel is installed into a clean
  environment and `mandate demo` runs from it. Nothing is uploaded to PyPI
  until the project's name is settled; G254 keeps tokens out of the
  workflow for when it is. See `docs/RELEASING.md`.

### Changed
- `mandate mcp` answers a missing or invalid configuration with one line and
  exit 1, as `mandate gateway` does, and a missing `mcp` extra with the line
  that installs it — not a traceback.
- The README starts with how to install, and its "What this does not do"
  list no longer names MCP, three releases after the guard shipped. It now
  says what is actually out of scope, including guessing intent: every
  decision is deterministic policy over signed fields.
- Package metadata: project URLs, keywords, classifiers, and the license
  declared the PEP 639 way.

### Security
- **The install instructions fetched someone else's package.** The README and
  `docs/MCP.md` said `pip install "mandate[mcp]"`, but the PyPI project named
  `mandate` is an unrelated AWS Cognito wrapper: following them installed
  foreign code and no Mandate at all. Every install line now names the
  repository (`pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"`),
  and G253 refuses any line that would resolve `mandate` from PyPI. No PyPI
  name is claimed yet; that waits for a decision on the product name.
- **An approval without `created_at` was treated as created now**, so a
  signed approval stayed usable for as long as anyone kept it — the fault
  v0.9.0 closed for intents, still open one call later. `created_at` is now
  required on approvals (ten-minute window), and a malformed `not_after` is
  a refusal instead of an unhandled error (a 500 at the gateway).
  **Breaking** for API clients that build their own approvals without
  `created_at`; `Engine.approve` has always set it. (G249, G250)
- **A counterparty allow-list could be passed by naming no counterparty.**
  The list was consulted only when an intent carried one. A grant with
  `counterparties_allow` now denies an intent that carries an amount but no
  counterparty — a payment to nobody named — while a call that moves no
  money is not the list's to refuse. An MCP tool configured with
  `counterparty_from` refuses a call whose argument is missing, empty, or too
  long to judge as sent. (G251, G252)

## [0.9.0] — 2026-09-22

Every gap the previous releases listed as open, closed or bounded. Each fix
was reproduced against the old code first and is pinned by gates that fail
against it (G202–G236).

### Security

- **HTTPS reached addresses the destination policy never approved.** The
  name was resolved for the check and again by httpx for the connection; a
  resolver that changed its answer sent an authorized request to an internal
  peer. TLS did not prevent it — whoever controls a name's DNS can hold a
  certificate for it. Both schemes now connect to the checked address; the
  name is used for SNI, certificate verification and `Host`. (G202–G203)
- **An environment proxy bypassed the destination policy.** With
  `HTTPS_PROXY` set, the proxy resolved the name itself. Proxy variables are
  ignored. (G204) Certificate verification cannot be disabled; a private CA
  bundle is loaded at startup. (G205)
- **A `base_url` path prefix was dropped when connecting** — `…/v2` + `/orders`
  went to `/orders`, while the receipt named `/v2/orders`. Present for HTTP on
  0.8.x. (G212)
- **The MCP guard ignored unknown configuration keys**, so a misspelt
  `max_daily_amount` issued a grant with no daily limit. Both configuration
  files are now read strictly, duplicates included. (G214, G217)
- **An intent without `created_at` was fresh forever**, defended only by a
  nonce kept forever. `created_at` is required. (G234)

### Added

- `mandate gateway check|serve --config` runs the HTTP gateway from one JSON
  file: routes, operations, enforcer signer, auth, rate limit, CA bundle,
  anchoring. `--workers N` shares one ledger. (G213, G215, G216, G219)
- `principal_signer` for the MCP guard: the grant-issuing key can stay in a
  key manager; `mcp init` then writes no principal key. (G218)
- `Engine.resolve_unknown`, `mandate gateway|mcp unknown` and `… resolve`:
  an operator's finding about an `EXECUTION_UNKNOWN` receipt is signed and
  chained into it, and the reservation is committed or released. The state
  machine allows exactly `EXECUTION_UNKNOWN → EXECUTED | EXECUTION_FAILED`.
  (G220–G222, G224)
- `mandate chain anchor --witness URL` and the gateway's `anchoring` block
  post chain heads to an external witness; workers share the schedule. Every
  failure is loud. (G229–G232)
- `LedgerRateLimiter`, the gateway's default: one bucket per key across every
  worker serving a ledger. (G207–G210)

### Fixed

- **A transaction that failed to begin kept the ledger lock**, hanging every
  later transaction on other threads — reachable as soon as several processes
  share the file and one gets `database is locked`. (G211)
- **Nothing is sent whose outcome the enforcer cannot sign.** With AWS KMS's
  4096-byte cap, an unbounded upstream error pushed the result receipt past
  it after dispatch; the outcome was lost and the receipt stayed EXECUTING.
  Error text is bounded to 200 one-byte characters, and an execution whose
  receipt could outgrow the signer is DENIED before anything is sent.
  (G226–G228)
- **Settlement of receipts from before budget bindings used today's date.**
  It now uses the recorded day or one the operator names, never a guess.
  (G223, G225)
- Nonces are pruned once the intents carrying them are stale, instead of
  being kept forever. (G233)
- `/v1/info` reported version 0.5.0; it now reports the package version, and
  README, changelog and pyproject are pinned to it. (G235–G236)
- The repository is lint-clean and CI runs a pinned ruff. A
  `DeprecationWarning` from this package fails the suite.

### Fixed after review

- **`"allow_insecure": "false"` enabled plain-HTTP Vault.** The string went
  through `bool()`, so the setting that says "no" switched the refusal off and
  the Vault token could travel in clear. Signer blocks are now validated per
  kind: unknown keys (a misspelt `did` lost its pin), wrong types and a
  non-boolean `allow_insecure` are errors. (G237)
- A non-canonical `--budget-day` (`2026-9-20`) would settle a day that
  reserved nothing. (G238)
- A plain-http witness could be reached through `HTTP_PROXY`, which would read
  its token and could answer for it; an invalid witness port crashed the CLI.
  (G239)
- Ignoring proxy variables also dropped `SSL_CERT_FILE`/`SSL_CERT_DIR`; they
  are honoured again for upstream verification. (G240)
- `gateway check` now loads and signs with the development key `serve` would
  use, instead of only naming its path. (G241)
- `chain verify --anchors` exits non-zero when any line of the anchor file is
  not an anchor: a damaged only-anchor used to leave a truncated chain
  passing. (G242)
- Every schema check and migration runs inside one write transaction, so
  workers opening an old ledger together do not die on a duplicate column.
  `executescript`, which commits and releases the lock, is no longer used
  during migration. (G243)
- `rotate_signer` (from 3170b1a, which reached `main` unreviewed) refuses to
  run on an engine whose key is not the chain's active signer. It used to
  append a rotation the chain's own verifier rejects. (G244)
- An unknown signer kind in the MCP guard's file is refused when the file is
  read, not when the signer is first built. (G245)
- A malformed URL (an unclosed `[`) is a configuration error, not a crash.
  (G246)
- An IPv6 upstream gets a bracketed `Host` header. (G247)
- A resolution too long for a capped enforcer signer is measured before the
  key manager is asked, and the error says how many bytes to cut; nothing is
  changed. The pre-dispatch check keeps room for a 32 + 128 character
  finding, not for the longest one accepted. (G248)

### Changed

- An intent must carry `created_at`.
- `mandate chain anchor` takes `--file`, `--witness` or both.

## [0.8.1] — 2026-09-22

### Fixed

- **The landing page advertised 218 gates while the suite had 222.** Nobody
  lied; the number was typed once and the suite grew. That is the ordinary way
  a page drifts, and it is why the number now has to be *derived*. A project
  whose argument is that claims should be checkable rather than believed
  cannot leave the first claim a visitor could check unchecked. New gates pin
  the advertised count, every gate id the page cites, and the version in the
  nav badge and footer — the page had also run three releases behind before
  this.
- **The anchor file's shape is now bounded at the reader.** That path had been
  wrong twice in two different ways — a `seq` that could not be hashed crashed
  the run, and garbage values were announced as real anchor divergence — both
  caught downstream, one field at a time. `mandate chain anchor` writes
  `{tenant, seq, entry_hash}`, so anything else is reported with its line
  number and dropped. A well-formed anchor that simply disagrees with the
  chain is still a finding, not garbage: shape is the reader's business,
  content is the verifier's.

## [0.8.0] — 2026-09-22

Closes what the last three releases listed as residual risk. Two of the three
could not be *solved* — a prefix of a valid chain is a valid chain, and a
stolen key signs whatever it likes — so they are answered with a mechanism
that bounds them instead of a paragraph that admits them.

### Added

- **Anchors.** `mandate chain anchor --file <path>` appends the current head,
  per tenant, to a file kept outside the database; `mandate chain verify
  --anchors <path>` checks every recorded head still stands. Truncation is
  invisible from inside a database by construction — this is the first thing
  in the project that does something about it rather than advising the reader
  to. It also catches history rewritten *beneath* a head somebody already
  wrote down. Gates G193, G194.
- **Key rotation.** `mandate chain rotate --to <did>` appends a rotation entry
  **signed by the key being replaced**. A chain was previously pinned to one
  key for life: rotating broke verification, so the practical advice was never
  to rotate, which leaves a single compromise unbounded in time. Whoever
  steals the current key still cannot rewrite anything that preceded the
  rotation, and cannot declare themselves the signer. Gates G195, G196, G197.
- `Engine.anchor_chain()` and `Engine.rotate_signer()`.

### Changed

- **Verification checks that a receipt's states form a legal road**, not only
  that its destination matches. Reconciliation compares against the chain's
  last entry for a receipt and says nothing about how it got there, so a
  history that skips authorization or walks backwards used to pass. This was
  a stated assumption in `SECURITY_BACKLOG.md`; it is now a check. Gates G190,
  G191 — and G192, which asserts a legal road is *not* a finding, because a
  check that condemns every history establishes nothing.
- One place decides whether a report is `ok`. The verdict used to be set
  inside whichever block happened to run, which is how a finding ends up in a
  report that still says ok.

### Fixed before review saw it

- **The rotation marker was a hiding place.** Rotation gave the chain an entry
  kind that reconciliation deliberately skips — and that skip is a hole if a
  *receipt row* can wear the same name. A row whose id column is
  `chain:signer-rotation`, copied from a genuine receipt so its proof still
  verifies, was invisible twice over: `unchained_receipts` found the rotation
  entry and called the row chained, and reconciliation skipped that entry so
  nothing compared it. Closed from both sides — the count no longer credits a
  rotation entry as cover for a receipt, and a receipt row carrying the
  reserved id is a finding in itself. Introduced by this release's own
  feature, found by asking what the reserved name could be turned into.
  Gate G198.
- A hostile anchor file was checked for the failure mode that has bitten this
  code three times: it may add noise, and may not remove a finding or end the
  run. Garbage seqs, a null tenant, unparseable lines and `1e400` all produce
  findings while the real tampering in the same database is still reported.
  Gate G199.

- **The no-op rotation guard was half-right.** It compared the incoming key
  against `head["signer"]` — but after a rotation the head *is* the rotation
  entry, whose `signer` is the key that left and whose `outcome` is the key in
  charge. A second, redundant rotation to the key already active therefore
  passed. It now compares against the active signer. Found by review; a guard
  that is right only before the first rotation is the worst kind of right.
- **A hostile anchor could still end the run.** `check_anchors` used the
  anchor's `seq` as a dictionary key, so a list-valued one raised `TypeError`
  out of `verify_chain` and took every later finding with it — the fourth time
  that shape has emptied this report. `seq` is now required to be an integer,
  and anything else is reported as unusable rather than crashing or, worse,
  being announced as a real anchor divergence. G199's own hostile file had
  used only *hashable* garbage, so the negative control had been proving that
  the verifier survives polite input.

### Still open

A chain cannot prove what was removed from its own end *without an anchor*, so
anchors have to actually be kept somewhere the operator cannot reach — the
tool now writes them, where they go remains a deployment decision. A
compromised enforcer key still signs whatever it likes from the moment it is
taken until it is rotated away; rotation bounds the window, it does not close
it. Route and key configuration outside code, and nonce pruning, remain
unimplemented.

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

- **A malformed DID still escaped, after the first fix.** `verify` decodes the
  DID before its own `try`, so a `verificationMethod` that is a string but not
  a `did:key` — `"not-a-did"`, an empty string, a `did:web` — raised
  `ValueError` out of `verify_object`. `mandate chain verify` survived it on
  the row boundary; `mandate verify` on a file did not, and produced exactly
  the traceback this release set out to remove. The whole operation now fails
  closed behind one boundary rather than a check per field: checking fields
  encodes a guess about what malformed input can do, and that guess was wrong
  again. Gates G186, G189.

- **G189 proved less than it looked like it proved.** It asserted the exit
  status alone, so a `mandate verify` that printed `VALID` and returned 1
  would have satisfied it. It now asserts the printed verdict in both
  directions — `INVALID` for each hostile file, and `VALID` with exit 0 for a
  genuine one, without which the gate is satisfied by a command that condemns
  everything. A test that overstates what it checks is the same failure as a
  verifier that says nothing.

- **Three gates established a failure, but not the failure they claimed.**
  G188 asserted that the report was not OK and that an unrelated rollback was
  still visible — a verifier that ignored the edited body entirely would have
  passed it. G176's second variant asserted only `not ok`, where the claim is
  that the links break at a named position. G189's positive case signed a
  hand-built dict rather than using a receipt from the pipeline, and allowed a
  caught traceback on stderr. All three now assert the content they are about.
  Asking whether other gates had the same shape was worth more than any single
  fix in this release.

Gates G186-G189. Full suite: 210 passed on Python 3.11 and 3.13.

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
