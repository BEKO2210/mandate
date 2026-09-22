# The receipt chain

A signed receipt proves who wrote it and that its contents are intact. It
proves nothing about the *set* of receipts. Until v0.7.0 an operator with
database access could delete a row, roll a state back, or insert one, and every
remaining signature still verified — the strongest guarantee in the system said
nothing about the thing it was supposed to be evidence of.

Every state a receipt reaches now appends an entry that commits to the entry
before it:

```
entry_hash(n) = sha256(canonical_json({seq, tenant, prev, receipt_id,
                                       outcome, body_hash, recorded_at}))
prev(n)       = entry_hash(n-1)
prev(1)       = sha256("mandate/chain/v1:" + tenant + ":" + legacy_receipts)
```

Each entry is signed by the enforcer over its own hash. Changing or removing
one changes its hash, which breaks `prev` on every entry after it; hiding that
means forging a signature on each of them.

## Two halves, and the second is the one that matters

**The chain verifies itself.** Links, sequence, signatures, tenant.

**The chain is reconciled against the receipts.** Every receipt the chain
records must still exist, still be in the state the last entry gave it, and
still hash to what that entry recorded.

The second half is not an extra. The first version of this feature had only the
first, and it caught *nothing*: deleting a receipt row left the chain perfectly
intact and internally consistent, because nothing ever looked at the rows the
chain commits to. That was found by deleting a row and asking the verifier, not
by reading the code. Gates G165–G168 exist because of it.

| What an operator does with a SQL prompt | Caught by |
|---|---|
| Delete a receipt row | reconciliation |
| Roll a receipt's state back | reconciliation |
| Edit a receipt's contents | reconciliation (canonical hash) |
| Insert a receipt around the chain | reconciliation (count vs. the chain) |
| Delete a chain entry | the walk, at that seq |
| Reorder entries | the walk, at that seq |
| Replay a real entry elsewhere | a unique index on `entry_hash` |
| Re-sign part of the chain | the walk (one signer throughout) |
| Reformat a receipt's JSON | **nothing — and correctly so.** The hash is canonical; whitespace is not tampering |
| Add a duplicate JSON member | the strict parser: `json.loads` keeps the last of a repeated key, so prepending one changes the stored bytes while the canonical hash stays put |
| Raise the legacy baseline in `meta` | genesis, which binds it |
| Insert a receipt into a tenant that has no chain | the verifier enumerates tenants from the receipts as well as the chain |

## Verify

```bash
$ mandate chain verify --db .mandate/mandate.sqlite
tenant default: 13 entries intact, head sha256:6854e2a8…, signed by did:key:z6MkimZW…
Note: without --expect-head, entries deleted from the end of the chain cannot be detected.
```

and when something is wrong:

```bash
$ mandate chain verify --db .mandate/mandate.sqlite
tenant default: TAMPERED — receipt rcpt_1c58a954… is in the chain at seq 13 but no longer in the database
  ! receipt rcpt_1c58a954… is in the chain at seq 13 but no longer in the database
$ echo $?
1
```

Verification reads the database directly and **needs no key and no running
gateway**. That is deliberate: the person who most needs to check a chain is
the one who does not trust whoever runs it. An early version required the
enforcer key and therefore reported every healthy chain as broken when run by
anyone else — a verifier that cries wolf is worse than none.

Without an expected signer, the walk pins every entry to the signer the first
one names. That catches a chain re-signed in part. Catching one re-signed end
to end needs the real enforcer DID:

```bash
mandate chain verify --db … --expect-signer did:key:z6MkimZW…
```

## What a chain cannot do

**Truncation.** A prefix of a valid chain is itself a valid chain. Nothing
inside a database can prove the absence of something removed from the end of
it. Deleting the last N entries *and* the receipts they cover leaves a
perfectly verifiable ledger that is simply shorter.

The only defence is a head held where the operator cannot reach it:

```bash
$ mandate chain head --db .mandate/mandate.sqlite
tenant : default
seq    : 13
head   : sha256:6854e2a8…
Keep this where the operator of this database cannot reach it.

$ mandate chain verify --db … --expect-head sha256:6854e2a8…
tenant default: BROKEN at seq 10: the chain ends at sha256:0e022192… but
sha256:6854e2a8… was expected; entries after that point are missing
```

The HTTP gateway hands the head to every authenticated caller on `/v1/info`, so
the people the receipts are *about* can keep one. A head in someone else's
hands turns truncation from invisible into provable. Where those heads go —
a log, a second host, a customer, a witness service — is a deployment decision
this codebase cannot make for you.

**A compromised enforcer key.** Someone holding it can re-sign the receipts and
the whole chain together, consistently. The chain raises the cost of editing
history from "run an UPDATE" to "hold the signing key"; it does not survive the
key itself being taken. That is the argument for `docs/KMS.md`.

**Anything a receipt never recorded.** The chain is evidence about receipts,
not about the world.

## Upgrading

Schema version 4 creates the chain empty and records how many receipts each
tenant already had. Seeding it from existing receipts would produce a chain
that *looks* like it covered them all along. It did not, and a verifier has to
be able to say so:

```
tenant default: 0 entries intact, head -
  - 3 receipt(s) predate the chain and are outside it
```

Those receipts are reported as a note, not a finding. Once the count of
unchained receipts exceeds what was there at the upgrade, rows were written
around the chain, and that *is* a finding.

That baseline lives in `meta`, where an operator can write — so raising it by
one would otherwise licence exactly one forged receipt, with no key needed. It
is bound into the chain's genesis instead: entry 1 points at
`sha256(prefix + tenant + ":" + baseline)`, so changing the baseline breaks the
chain at its first link.

The baseline is therefore **trusted on first use** and immutable in effect from
the first chained write onwards. A tenant whose chain is still empty has
nothing to break, which is the one window where it can still be set. Review
found this; it was an unsigned bypass of every count-based check before.

## Shape

A hash chain, not a Merkle tree. A chain gives the property that matters here —
append-only, detectably — in code short enough to audit, and the verifier walks
everything anyway. A tree buys efficient inclusion proofs for a third party who
will not read the whole log; nothing in Mandate asks for that yet. When
something does, the entry format is the thing to change.

Chains are per tenant. One tenant's activity does not advance another's
sequence, and genesis binds the tenant name, so an entry cannot be spliced from
one chain into another. A verifier given no `--tenant` therefore has to
enumerate tenants from the *receipts* as well as the chain: a tenant with rows
and no entries is not an empty tenant, it is the shape an insert around the
chain has. The cost is that a whole tenant's chain can be dropped
without any other tenant noticing — the same isolation the rest of the system
already chose.

## Cost

Verification loads a tenant's entries and rehashes its receipts, so it is
linear in the ledger and meant to be run deliberately — from a cron job, an
audit, an incident — not per request. Writing costs one extra signature per
receipt state, on the same key and inside the same transaction: a receipt and
its chain entry land together or not at all.
