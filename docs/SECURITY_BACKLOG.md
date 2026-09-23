# Security hardening backlog after v0.2

This file tracks narrowly scoped follow-ups discovered during independent review of the remotely reproducible v0.2 Golden tree.

## SH-01 — Budget reservation day must be stable — DONE in v0.2.1

Authorization now records a `budget_bindings` row (receipt_id, grant_id, currency, day, amount) at reserve time. Commit, release, and EXECUTION_UNKNOWN handling use that bound day. Engine clock is injectable for tests; production uses UTC `utcnow()`.

Covered by G41–G44.

## SH-02 — Route destination resolution policy — DONE in v0.2.1

`Route.network_policy` defaults to `"public"`. Loopback/RFC1918 require explicit server-side `"allow_private"`. Metadata hosts and link-local addresses stay blocked even under `allow_private`. Hostnames are resolved with `getaddrinfo`; any blocked address fails closed.

HTTP connections pin the first allowed IP and send the original Host header. Since v0.9.0 HTTPS does too: it connects to the validated IP and keeps the hostname for SNI and certificate verification, and proxy environment variables are ignored (G202–G206).

Covered by G45–G52.

## SH-03 — Request body limit before buffering — DONE in v0.2.1

`BodyLimitMiddleware` rejects `Content-Length > MAX_BODY` without reading the body. Chunked/missing-length bodies are counted as they arrive and abort at `MAX_BODY + 1`.

Covered by G53–G57.

## SH-04 — Money must be exact — DONE in v0.2.2

Float amounts decided caps wrongly: 0.10 + 0.20 against a 0.30 daily cap was
denied, and ten 0.10 reservations against a 1.00 cap accumulated to
0.9999999999999999. Amounts, constraints and budgets are now integer minor
units (`mandate/money.py`), converted once at the validation boundary from the
same decimal text the signature covers. An amount finer than the currency is
refused rather than rounded into a budget. Ledger schema version 2 converts
legacy float rows half-up, once, on first open.

Covered by G58-G63 and G68.

## SH-05 — A claimed execution must reach a terminal state — DONE in v0.2.2

`AUTHORIZED -> EXECUTING` stored the previous signed body, so the ledger said
EXECUTING while the receipt said AUTHORIZED, and a retry returned that body for
a request that may already have been dispatched. The claim is now signed as
EXECUTING. Any exception out of the executor becomes EXECUTION_UNKNOWN with the
reservation kept, and `Engine.reconcile_stale_executions()` closes out claims
whose process died; the gateway runs it at startup.

Covered by G64-G67.

## SH-06 — The request body must be decided server-side and bound — DONE in v0.3.0

Until 0.2.2 only `allowed_methods[0]` and `allowed_paths[0]` were dispatched
with a fixed four-field body, so the gateway could not carry real work and the
receipt said nothing about the bytes that left it. A route now declares an
`Operation` per signed action: method, path, an allowlist of intent fields and
an allowlist of `context` keys. The enforcer builds the body, hashes it, and
signs that hash into the receipt before dispatch; the executor sends exactly
those bytes. Undeclared fields never travel, non-scalar or oversized values are
refused, and an operation cannot widen its route's method or path allowlist.

Covered by G70-G79.

## SH-07 — The gateway must know who is calling — DONE in v0.4.0

Signed objects proved who authored a grant. They never said who may reach the
gateway. Anyone who could open a socket could submit intents and read any
receipt whose id they held.

Every endpoint but `/health` now requires an API key. Only the SHA-256 of a
256-bit secret is stored, comparison is constant time, and an unknown key id
follows the same path as a wrong secret. Keys carry scopes, an optional expiry
and a disable switch, and a per-key token bucket answers 429.

Records belong to a tenant and the key decides which one. Another tenant's
grant or receipt reads as absent rather than forbidden, so a valid key cannot
be used as an existence oracle. Nonces carry the tenant in their primary key,
so one tenant cannot burn another's. Routes are resolved within a tenant.

`create_app()` refuses to build an unauthenticated gateway; that has to be
chosen out loud with `OpenAccess()`.

Covered by G81-G98.

## SH-08 — A signing key must not be a file the signing process can read — DONE in v0.6.0

Every private key was an `Ed25519PrivateKey` in the memory of the process that
signed with it, loaded from a file beside the ledger. The MCP guard made the
cost concrete: it held the agent key in the same process a model talks to, so
the key survived any compromise of that process and kept working wherever it
was copied.

A signer is now anything that can name a DID and sign bytes. `mandate/signing.py`
adds AWS KMS (`ECC_NIST_EDWARDS25519`), Cloud KMS (`EC_SIGN_ED25519`), Vault
transit (`ed25519`) and an external command for HSMs. Every remote signature is
verified against the signer's DID before it is returned, so a mispointed key
manager fails at sign time rather than producing an unverifiable receipt. With
a signer configured, `mandate mcp init` generates and writes no agent key at
all, and a signer that cannot sign refuses the call with nothing dispatched.

Residual, and stated rather than fixed: a key manager does not stop code
already running in the signing process from asking for signatures. It removes
the exfiltratable secret and makes revocation effective; an audit trail comes
from the provider, where that provider keeps one. The grant's limits remain
what bound a live compromise.

Independent review of this change found four further defects, all fixed here:
a malformed configured DID escaped as `ValueError` past every `SigningError`
handler; `urllib` forwarded `X-Vault-Token` to a redirect target, cross-origin
and across an https-to-http downgrade (reproduced against a live server); a
`SigningError` after dispatch was reported as a failed dispatch, inviting the
retry that must not happen; and the enforcer signer was never proven to sign
before the guard exposed its tools.

A second pass found the same defect one line further down, in the place the
first fix had deliberately left alone: losing the final state race to the
reconciler raised `MandateError("invalid state transition")` after dispatch,
which the guard reported as a failed dispatch. It now raises `ExecutionUnknown`
like every other post-dispatch failure.

Covered by G120-G157.

## SH-09 — History must not be editable without evidence — DONE in v0.7.0

Every receipt was individually signed and nothing tied them together, so an
operator with database access could delete a receipt, roll its state back, or
insert one, and every remaining signature still verified.

Each receipt state now appends an enforcer-signed entry to a per-tenant hash
chain, in the same transaction as the write; the ledger refuses a receipt write
that carries no entry. `mandate chain verify` walks the chain *and* reconciles
it against the receipts it commits to, needing no key and no running gateway so
that someone who distrusts the operator can run it.

The reconciliation half was missing from the first implementation, which caught
nothing: deleting a row left the chain perfectly self-consistent. That was
found by performing the attack, not by review of the code, and G165-G168 are
written as the attacks rather than as the feature.

Residual, stated rather than fixed: a prefix of a valid chain is a valid chain,
so truncation is invisible from inside the database. `/v1/info` and `mandate
chain head` hand out a head to keep elsewhere, and `--expect-head` checks
against it; where that head goes is a deployment decision. A compromised
enforcer key still allows receipts and chain to be re-signed together.

Independent review then found three ways past it, all fixed: the legacy
baseline was an unsigned value in `meta` that an operator could raise to
licence forged receipts; a duplicate JSON member changed a stored body without
changing its canonical hash; and a non-atomic schema-4 migration could inflate
the baseline under concurrency.

Covered by G158-G180.

## SH-10 — The policy must hold at the socket, and the limit across workers — DONE in v0.9.0

HTTPS connected by name, so the name was resolved a second time after the
destination check. A resolver that answered differently the second time sent
an authorized request to an internal address; TLS did not stop it, because
whoever controls a name's DNS can hold a certificate for it. HTTPS now
connects to the checked address and keeps the name for SNI and certificate
verification. With `HTTPS_PROXY` set, every request went to the proxy, which
resolved the name itself — proxy variables are now ignored. Certificate
verification cannot be disabled; a private CA path is loaded at startup.

The rate limit was a dict in one process's memory, so N workers gave a key N
times its limit. The bucket is now a ledger row. Writing it exposed a latent
hang: a transaction that failed to begin kept the ledger lock, so the next
one on any thread waited forever — and `database is locked` is an ordinary
answer once processes share the file.

Covered by G202–G211.

## SH-11 — A security boundary must be configurable without code — DONE in v0.9.0

The HTTP gateway could only be assembled in Python. `mandate gateway check`
and `mandate gateway serve` now run it from one JSON file: routes,
operations, enforcer signer, authentication, rate limit and CA bundle. The
file is read strictly, and so is the MCP guard's, which used to ignore
unknown keys — a misspelt `max_daily_amount` was dropped and the grant issued
with no daily limit. `principal_signer` keeps the grant-issuing key in a key
manager.

Reading the executor for this found a path bug: connecting to the pinned
address rebuilt the URL from the operation's path alone, so a `base_url` of
`https://api.example/v2` sent `/v2/orders` to `/orders`. The receipt named
one path and the upstream was asked for another.

Covered by G212–G219.

## SH-12 — An unknown outcome must be resolvable without editing the ledger — DONE in v0.9.0

`EXECUTION_UNKNOWN` was a dead end: its reservation stayed held forever, so
every unknown outcome permanently shrank a grant's daily budget, and the only
way for a person who knew what happened to say so was to edit the database.
`resolve_unknown` (`mandate gateway resolve`, `mandate mcp resolve`) records
the finding as a signed, chained transition to `EXECUTED` (commit) or
`EXECUTION_FAILED` (release), naming who decided and why.

Settlement for receipts from before budget bindings fell back to *today*.
`execute()` refuses such receipts before dispatch, so there it was dead code;
resolution is where they still arrive. The day is now the recorded one, or one
the operator names — never a guess, and never overriding a recorded day.

Covered by G220–G225.

## SH-13 — Nothing may be sent whose outcome cannot be signed — DONE in v0.9.0

With the enforcer key on AWS KMS (4096-byte cap), a receipt whose claim fit
could produce a result that did not: the executor's error text was unbounded.
Reproduced with a 1100-byte context and a verbose 502 — the request was sent,
the outcome could not be signed, and the receipt stayed EXECUTING until the
next restart. Error text is now bounded to 200 one-byte characters, and before
dispatch the engine sizes the largest body it could ever sign for the
execution; if that exceeds the signer's cap the receipt is DENIED and nothing
is sent.

Covered by G226–G228.

## SH-14 — Heads must leave the operator's reach without a runbook — DONE in v0.9.0

`mandate chain anchor` wrote heads to a file; whether that file was beyond the
operator's reach was left to the operator. `--witness` posts them to an HTTPS
endpoint run by someone else, and the gateway's `anchoring` block does it on a
schedule, once per interval across all workers. Every failure is loud: a
non-2xx, a redirect, an unreachable witness or a missing token exits non-zero
or stops the gateway from starting.

Covered by G229–G232.

## SH-15 — Replay protection must not need infinite memory — DONE in v0.9.0

Every consumed nonce was kept forever. Pruning is safe only once the intent
carrying a nonce can no longer pass the freshness check — and an intent
without `created_at` passed it forever, because a missing value was read as
"now". `created_at` is now required, and a nonce is dropped once it is older
than the freshness window plus clock skew plus a minute.

`/v1/info` also reported version 0.5.0 through four releases; it reads the
package version now, and the README, changelog and pyproject are pinned to it.

Covered by G233–G236.

## SH-16 — An approval must carry its own creation time — DONE (unreleased)

`submit_approval` read a missing `created_at` as "now", the same default
SH-15 removed for intents: an approval signed once and kept could be replayed
at any later time while its receipt waited. Only the receipt's own state
stood in the way. `created_at` is required, the window is ten minutes, and a
malformed `not_after` is refused rather than raised.

Covered by G249–G250.

## SH-17 — An allow-list is not skipped by an absent counterparty — DONE (unreleased)

`counterparties_allow` was checked only `if intent.counterparty`. An MCP call
that simply left its vendor argument out reached the upstream under a grant
that named the only vendors it could pay. A grant with an allow-list now
denies an intent that carries an amount but names no counterparty — a call
that moves no money pays nobody and is not the list's to refuse — and a tool
mapped with
`counterparty_from` refuses the call when the argument is missing, empty, or
longer than the field can hold — cut to fit, the value judged would not be
the value sent. A deny-list still applies only to a named counterparty; it
cannot express "unknown is bad", and an allow-list is how to say that.

Covered by G251–G252.

## Residual / next

- A chain cannot prove what was removed from its own end; truncation is only
  detectable against a head kept outside the deployment. The gateway now posts
  heads to a witness on a schedule (`anchoring`) and `mandate chain anchor
  --witness` does it on demand, so what remains is choosing a witness the
  operator does not control — which no software can do for them
- The chain is signed by the enforcer key; a compromise of that key allows
  history and chain to be re-signed together, from the moment it is taken
  until it is rotated away. `mandate chain rotate` bounds that window — the
  rotation entry is signed by the outgoing key, so a thief cannot reach back
  past it — but nothing bounds what the key does while it is held
- The legacy baseline is trusted on first use: a tenant whose chain is still
  empty has no entry for genesis to break. What that window buys an operator
  is bounded by the proof check — a licensed row is still read, and a row
  nobody signed is still a finding
- The request hash binds what the gateway sent, not what the upstream received
- A key manager does not bound a live compromise of the signing process
- AWS KMS caps a signed message at 4096 bytes. An execution whose receipt
  could exceed it is refused before dispatch, so the cost is capacity — less
  room for context — not a lost outcome
- Without `principal_signer`, `mcp init` writes the grant-issuing key to the
  store as a development file; that is a default an operator has to change
- Resolving an EXECUTION_UNKNOWN receipt records an operator's finding; the
  engine cannot check it against the upstream, and the receipt says so by
  naming who decided
