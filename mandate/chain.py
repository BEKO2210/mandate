"""A receipt chain: history that cannot be edited without showing it.

Every receipt is individually signed, which proves who wrote it and that its
contents are intact. It proves nothing about the *set* of receipts. An operator
with database access could delete a row, roll a state back, or reorder history,
and every remaining signature would still verify — the strongest guarantee in
the system said nothing about the thing it was supposed to be evidence of.

This module is the missing link. Each state a receipt reaches appends an entry
that commits to the entry before it:

    entry_hash(n) = sha256(canonical_json({seq, tenant, prev, receipt_id,
                                           outcome, body_hash, recorded_at}))
    prev(n)       = entry_hash(n-1)

Changing or removing any entry changes its hash, which breaks `prev` on every
entry after it. An operator who edits history has to forge the enforcer's
signature on every later entry to hide it, which is the same problem as forging
a receipt.

It is deliberately a hash chain and not a Merkle tree. A chain gives the
property that matters here — append-only, detectably — in code short enough to
audit, and Mandate's verifier walks the whole chain anyway. A tree buys
efficient inclusion proofs for a third party who will not read everything, and
nothing in Mandate asks for that yet.

**What a chain does not do.** A prefix of a valid chain is itself a valid
chain, so deleting from the *end* stays undetectable from the inside — nothing
in the database can prove the absence of something that was removed. Detecting
truncation needs a head kept somewhere the operator does not control:
`Engine.chain_head()` hands out exactly that, and `verify_chain(expect_head=…)`
checks against one you kept. Where that head goes is a deployment decision this
module cannot make.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .crypto import canonical_json, did_to_public_bytes, sha256_hex, verify

#: Bound into the first entry so a chain cannot be spliced onto another
#: tenant's history: a stolen entry carries the tenant it was written for.
GENESIS_PREFIX = b"mandate/chain/v1:"

#: The keys an entry commits to. Anything outside this set is not covered by
#: the hash, so nothing outside it may be trusted.
ENTRY_FIELDS = ("seq", "tenant", "prev", "receipt_id", "outcome", "body_hash", "recorded_at")

#: A chain entry that records a change of signing key rather than a receipt.
#: It reuses `receipt_id` and `outcome` instead of adding fields, so the hash
#: covers it exactly as it covers everything else — a rotation an attacker
#: could add outside the hash would be no rotation at all.
ROTATION_ID = "chain:signer-rotation"

#: The states a receipt can be *created* in. Evaluation happens before the
#: first write, so a receipt may enter the chain already denied or already
#: authorized — but never already executed. A first entry outside this set
#: describes a history that cannot have happened, which is the shape of a
#: forgery that skips authorization and lands on the result.
INITIAL_OUTCOMES = frozenset({"PROPOSED", "DENIED", "HUMAN_REQUIRED", "AUTHORIZED"})


class ChainError(Exception):
    """The chain does not say what it claims to say."""


class UnusableBody(ValueError):
    """The stored JSON cannot be treated as a document at all."""


class DuplicateMember(UnusableBody):
    """The stored JSON has the same key twice."""


def _reject_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateMember(f"duplicate member {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str):
    # NaN and Infinity are Python's extensions to JSON, not JSON. A body
    # carrying one canonicalises to bytes no conforming parser will read back.
    raise UnusableBody(f"{name} is not a JSON value")


def loads_strict(raw: str) -> Any:
    """Parse a stored body, refusing anything an auditor could not read back.

    Three refusals, each of them a way to change the bytes on disk without
    changing what the canonical hash commits to:

    **Duplicate members.** `json.loads` keeps the last of a repeated key, so an
    operator can prepend `"outcome": "DENIED"` to a receipt and leave the hash
    unchanged while the stored bytes read differently to any parser that keeps
    the first.

    **Unpaired surrogates.** ``"\\ud800"`` is a legal JSON escape and an
    illegal Unicode string. It parses, and then `canonical_json` raises
    `UnicodeEncodeError` on the way out — which crashed the verifier mid-run
    and took the whole report with it, including findings about *other*
    receipts. Refusing it here turns a blinded verifier into a named finding.

    **NaN and Infinity.** Python accepts them; JSON does not.

    The bytes on disk are what an auditor is handed, so a document two parsers
    disagree about is already tampered with.
    """
    value = json.loads(raw, object_pairs_hook=_reject_duplicates,
                       parse_constant=_reject_constant)
    try:
        # The same encode `body_hash` will do, done here where it can be
        # reported rather than there where it cannot.
        canonical_json(value)
    except UnicodeEncodeError as exc:
        raise UnusableBody(f"text that is not valid Unicode ({exc})") from exc
    return value


def genesis(tenant: str, legacy_receipts: int = 0) -> str:
    """The value entry 1 points at.

    It binds the tenant — so an entry cannot be spliced from one chain into
    another — and the number of receipts that already existed when the chain
    started. That second part is what stops the baseline from being edited:
    it lives in `meta`, where an operator can write, and raising it would
    otherwise licence exactly the unchained inserts it is meant to bound.
    Changing it now breaks entry 1, and with it every entry after.

    The baseline is therefore trusted on first use and immutable in effect
    from the first chained write onwards. A tenant whose chain is still empty
    has nothing to break, which is the one window where it can still be set.
    That window buys little: `verify_chain` reads every receipt's own proof,
    so a licensed row that nobody signed is still a finding.
    """
    seed = GENESIS_PREFIX + tenant.encode("utf-8") + b":" + str(int(legacy_receipts)).encode()
    return "sha256:" + hashlib.sha256(seed).hexdigest()


def body_hash(signed_body: dict[str, Any]) -> str:
    """Hash the receipt *as stored*, proof included.

    Covering the signature too means that re-signing an altered receipt — with
    a leaked enforcer key, say — still breaks the chain.
    """
    return "sha256:" + sha256_hex(canonical_json(signed_body))


def entry_body(
    *, seq: int, tenant: str, prev: str, receipt_id: str, outcome: str,
    body_hash: str, recorded_at: str,
) -> dict[str, Any]:
    return {
        "seq": seq,
        "tenant": tenant,
        "prev": prev,
        "receipt_id": receipt_id,
        "outcome": outcome,
        "body_hash": body_hash,
        "recorded_at": recorded_at,
    }


def entry_hash(body: dict[str, Any]) -> str:
    covered = {k: body[k] for k in ENTRY_FIELDS}
    return "sha256:" + sha256_hex(canonical_json(covered))


def sign_entry(signer, body: dict[str, Any]) -> dict[str, Any]:
    """Sign the entry's hash, not its body.

    The hash is what the next entry points at, so signing it binds the
    signature and the link to the same bytes.
    """
    digest = entry_hash(body)
    return {
        **body,
        "entry_hash": digest,
        "signer": signer.did(),
        "signature": signer.sign_hex(digest.encode("ascii")),
    }


def is_rotation(entry: dict[str, Any]) -> bool:
    return entry.get("receipt_id") == ROTATION_ID


def rotation_body(*, seq: int, tenant: str, prev: str, new_signer: str,
                  recorded_at: str) -> dict[str, Any]:
    """An entry that hands signing authority to another key.

    Signed by the key being *replaced*, which is the whole point: a stolen
    current key cannot rewrite the history that precedes the rotation without
    also holding the key that signed it. Without this, a chain is pinned to
    one key forever — rotating would break verification, so nobody would — and
    a single compromise would be unbounded in both directions.
    """
    try:
        did_to_public_bytes(new_signer)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ChainError(f"{new_signer!r} is not an Ed25519 did:key: {exc}") from exc
    return entry_body(
        seq=seq, tenant=tenant, prev=prev, receipt_id=ROTATION_ID,
        outcome=new_signer,
        body_hash="sha256:" + sha256_hex(new_signer.encode("utf-8")),
        recorded_at=recorded_at,
    )


def check_entry(entry: dict[str, Any], *, expect_seq: int, expect_prev: str,
                expect_tenant: str, signer_did: str | None = None) -> str | None:
    """Return why this entry is not the one that belongs here, or None."""
    for field_name in (*ENTRY_FIELDS, "entry_hash", "signature", "signer"):
        if field_name not in entry:
            return f"entry is missing {field_name}"
    if entry["seq"] != expect_seq:
        return f"expected seq {expect_seq}, found {entry['seq']}"
    if entry["tenant"] != expect_tenant:
        return f"entry belongs to tenant {entry['tenant']!r}, not {expect_tenant!r}"
    if entry["prev"] != expect_prev:
        return "prev does not match the previous entry's hash"
    recomputed = entry_hash(entry)
    if recomputed != entry["entry_hash"]:
        return "entry_hash does not match the entry's contents"
    if signer_did is not None and entry["signer"] != signer_did:
        return f"entry was signed by {entry['signer']}, not by {signer_did}"
    if not verify(entry["signer"], recomputed.encode("ascii"), entry["signature"]):
        return "signature does not verify"
    return None


def reconcile(
    entries: list[dict[str, Any]], stored: dict[str, dict[str, Any]]
) -> list[str]:
    """Compare what the chain recorded against what the database now holds.

    Found by trying it rather than by reasoning about it: a chain that only
    verifies itself catches nothing. Deleting a receipt row or rolling its
    state back leaves the chain perfectly intact and internally consistent,
    because nothing ever looked at the rows the chain commits to.

    The chain is the record of what happened; the receipts table is the claim
    about what is. Evidence is the comparison, not either one alone.
    """
    # Keyed on the highest seq rather than on arrival order: `verify_chain`
    # has already proven the order, but this function is callable on its own
    # and must not quietly compare against the wrong entry if it is not.
    latest: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if is_rotation(entry):
            continue  # a key change, not a claim about any receipt
        current = latest.get(entry["receipt_id"])
        if current is None or entry.get("seq", 0) >= current.get("seq", 0):
            latest[entry["receipt_id"]] = entry

    problems: list[str] = []
    for receipt_id, entry in latest.items():
        row = stored.get(receipt_id)
        if row is None:
            problems.append(
                f"receipt {receipt_id} is in the chain at seq {entry['seq']} "
                f"but no longer in the database"
            )
            continue
        if row.get("state") != entry["outcome"]:
            problems.append(
                f"receipt {receipt_id} is stored as {row.get('state')} but the chain's "
                f"last entry for it (seq {entry['seq']}) says {entry['outcome']}"
            )
        if row.get("error"):
            problems.append(f"receipt {receipt_id} cannot be read: {row['error']}")
            continue
        if row.get("body_hash") != entry["body_hash"]:
            problems.append(
                f"receipt {receipt_id} does not hash to what seq {entry['seq']} recorded; "
                f"its contents changed after it was chained"
            )
    return problems


def check_transitions(entries: list[dict[str, Any]]) -> list[str]:
    """Do the states the chain records for each receipt follow one another?

    Reconciliation compares a receipt against the chain's *last* entry for it
    and says nothing about the road taken to get there. Every ordinary write
    goes through `assert_transition`, so this only bites when something has
    written entries that the engine never would — a compromised signer, or a
    bug in a future writer. That was a stated assumption until now; an
    unstated assumption in evidence code is true right up until it is not.
    """
    from .states import can_transition

    seen: dict[str, str] = {}
    problems: list[str] = []
    for entry in entries:
        if is_rotation(entry):
            continue
        receipt_id, outcome = entry["receipt_id"], entry["outcome"]
        previous = seen.get(receipt_id)
        if previous is None:
            if outcome not in INITIAL_OUTCOMES:
                problems.append(
                    f"receipt {receipt_id} enters the chain at seq {entry['seq']} "
                    f"already {outcome}; no receipt is created in that state"
                )
        elif not can_transition(previous, outcome):
            problems.append(
                f"receipt {receipt_id} goes {previous} -> {outcome} at seq "
                f"{entry['seq']}, which the state machine does not allow"
            )
        seen[receipt_id] = outcome
    return problems


def check_anchors(entries: list[dict[str, Any]], anchors: list[dict[str, Any]],
                  tenant: str) -> list[str]:
    """Compare the chain against heads that were written down elsewhere.

    A prefix of a valid chain is a valid chain, so nothing inside a database
    can prove that its end was not cut off. The only defence is a head held
    where whoever runs the database cannot reach it — and until now this
    codebase gave that as advice rather than as something it does.
    """
    by_seq = {entry.get("seq"): entry for entry in entries}
    problems: list[str] = []
    for anchor in anchors:
        if anchor.get("tenant") != tenant:
            continue
        seq, expected = anchor.get("seq"), anchor.get("entry_hash")
        entry = by_seq.get(seq)
        if entry is None:
            problems.append(
                f"an anchor recorded seq {seq} for this tenant on "
                f"{anchor.get('anchored_at', 'an unknown date')}, and the chain "
                f"no longer reaches it"
            )
        elif entry.get("entry_hash") != expected:
            problems.append(
                f"seq {seq} is {entry.get('entry_hash')} but the anchor taken on "
                f"{anchor.get('anchored_at', 'an unknown date')} recorded "
                f"{expected}; history was rewritten under it"
            )
    return problems


@dataclass
class ChainReport:
    """What a walk of the chain found. `ok` is the only thing to branch on."""

    tenant: str
    ok: bool
    length: int
    legacy_receipts: int = 0
    signer: str | None = None
    head: str | None = None
    broken_at: int | None = None
    receipt_id: str | None = None
    reason: str | None = None
    unchained_receipts: int = 0
    rotations: int = 0
    anchors: int = 0
    mismatches: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.broken_at is not None:
            return (
                f"tenant {self.tenant}: BROKEN at seq {self.broken_at} "
                f"({self.receipt_id}): {self.reason}"
            )
        if self.mismatches:
            first = self.mismatches[0]
            more = f" (+{len(self.mismatches) - 1} more)" if len(self.mismatches) > 1 else ""
            return f"tenant {self.tenant}: TAMPERED — {first}{more}"
        signed_by = f", signed by {self.signer}" if self.signer else ""
        extra = ""
        if self.rotations:
            extra += f", {self.rotations} key rotation(s)"
        if self.anchors:
            extra += f", {self.anchors} anchor(s) hold"
        return (
            f"tenant {self.tenant}: {self.length} entries intact, "
            f"head {self.head or '-'}{signed_by}{extra}"
        )


def verify_chain(
    entries: list[dict[str, Any]], tenant: str, *,
    signer_did: str | None = None, expect_head: str | None = None,
    stored: dict[str, dict[str, Any]] | None = None,
    unchained_receipts: int = 0, legacy_receipts: int = 0,
    anchors: list[dict[str, Any]] | None = None,
) -> ChainReport:
    """Walk a tenant's chain from genesis and report the first break.

    The first break is the only interesting one: everything after it is
    unverifiable anyway, and naming a later entry would say nothing about
    where the history actually diverged.

    `signer_did` is optional because verification has to be runnable by someone
    who holds no key at all — an auditor, or the operator's customer. Left out,
    the walk requires every entry to carry the *same* signer as the first and
    verifies each signature against the DID the entry names, which catches a
    chain re-signed only in part. Catching one re-signed end to end needs the
    real enforcer DID, so pass it when you know it.
    """
    prev = genesis(tenant, legacy_receipts)
    expect_signer = signer_did
    rotations = 0
    for index, entry in enumerate(entries, start=1):
        if expect_signer is None:
            expect_signer = entry.get("signer")
        problem = check_entry(
            entry, expect_seq=index, expect_prev=prev, expect_tenant=tenant,
            signer_did=expect_signer,
        )
        if problem:
            return ChainReport(
                tenant=tenant, ok=False, length=index - 1, signer=expect_signer,
                legacy_receipts=legacy_receipts, head=prev if index > 1 else None,
                broken_at=index, receipt_id=entry.get("receipt_id"), reason=problem,
                unchained_receipts=unchained_receipts,
            )
        prev = entry["entry_hash"]
        if is_rotation(entry):
            # Verified a moment ago against the *outgoing* signer, which is
            # what makes a rotation an act of the key being replaced rather
            # than a claim by whoever holds the new one.
            expect_signer = entry["outcome"]
            rotations += 1

    head = prev if entries else None
    report = ChainReport(
        tenant=tenant, ok=True, length=len(entries), signer=expect_signer,
        legacy_receipts=legacy_receipts, head=head, unchained_receipts=unchained_receipts,
        rotations=rotations,
    )

    # The states a receipt passed through have to be a road the state machine
    # allows, not merely a destination that matches.
    report.mismatches.extend(check_transitions(entries))

    # Heads written down outside this database. The only thing that can speak
    # for what is missing from the end of a chain.
    if anchors:
        report.mismatches.extend(check_anchors(entries, anchors, tenant))
        report.anchors = sum(1 for a in anchors if a.get("tenant") == tenant)
    if expect_head is not None and head != expect_head:
        # The chain is internally consistent and still wrong: this is what a
        # truncation looks like from the outside, and the only way to see it.
        report.ok = False
        report.broken_at = len(entries)
        report.reason = (
            f"the chain ends at {head or 'nothing'} but {expect_head} was expected; "
            f"entries after that point are missing"
        )
    if stored is not None:
        report.mismatches.extend(reconcile(entries, stored))
        # The chain says what the set of receipts is. It never asked whether a
        # row in that set was ever signed, so a fabricated receipt in a tenant
        # the chain does not cover sat unexamined. Verifying a proof needs no
        # secret — only the DID the proof already names — so every receipt is
        # asked, chained or not.
        for receipt_id, row in sorted(stored.items()):
            if receipt_id == ROTATION_ID:
                # No receipt is ever created with this id — they are `rcpt_…`.
                # A row carrying the marker is an attempt to hide behind the
                # one entry kind that reconciliation deliberately skips.
                report.mismatches.append(
                    f"a receipt row carries the reserved id {ROTATION_ID!r}, "
                    f"which only a chain entry may use"
                )
                continue
            if row.get("error") or row.get("proof_ok", True):
                continue
            report.mismatches.append(
                f"receipt {receipt_id} does not carry a signature that verifies "
                f"against the key its own proof names"
            )

    # Receipts the chain never recorded. Up to the number that already existed
    # when the chain started, that is history the chain cannot speak for;
    # beyond it, rows were written around the chain.
    if unchained_receipts > legacy_receipts:
        inserted = unchained_receipts - legacy_receipts
        report.mismatches.append(
            f"{inserted} receipt(s) exist that the chain never recorded"
        )
        report.ok = False
    # One place decides. Each check above only reports; leaving the verdict to
    # whichever block happened to run last is how a finding ends up in a report
    # that still says ok.
    if report.mismatches:
        report.ok = False
    if legacy_receipts:
        report.notes.append(
            f"{legacy_receipts} receipt(s) predate the chain and are outside it "
            f"(this baseline is bound into the chain's genesis and cannot be raised "
            f"once the chain has an entry)"
        )
    return report
