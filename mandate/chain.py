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

from .crypto import canonical_json, sha256_hex, verify

#: Bound into the first entry so a chain cannot be spliced onto another
#: tenant's history: a stolen entry carries the tenant it was written for.
GENESIS_PREFIX = b"mandate/chain/v1:"

#: The keys an entry commits to. Anything outside this set is not covered by
#: the hash, so nothing outside it may be trusted.
ENTRY_FIELDS = ("seq", "tenant", "prev", "receipt_id", "outcome", "body_hash", "recorded_at")


class ChainError(Exception):
    """The chain does not say what it claims to say."""


class DuplicateMember(ValueError):
    """The stored JSON has the same key twice."""


def _reject_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateMember(f"duplicate member {key!r}")
        seen.add(key)
    return dict(pairs)


def loads_strict(raw: str) -> Any:
    """Parse a stored body, refusing duplicate members.

    `json.loads` keeps the last of a repeated key, so an operator can prepend
    `"outcome": "DENIED"` to a receipt and leave the canonical hash unchanged
    while the stored bytes now read differently to any parser that keeps the
    first. The bytes on disk are what an auditor is handed, so a document that
    two parsers disagree about is already tampered with.
    """
    return json.loads(raw, object_pairs_hook=_reject_duplicates)


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
    entries: list[dict[str, Any]], stored: dict[str, dict[str, str]]
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
        return (
            f"tenant {self.tenant}: {self.length} entries intact, "
            f"head {self.head or '-'}{signed_by}"
        )


def verify_chain(
    entries: list[dict[str, Any]], tenant: str, *,
    signer_did: str | None = None, expect_head: str | None = None,
    stored: dict[str, dict[str, str]] | None = None,
    unchained_receipts: int = 0, legacy_receipts: int = 0,
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

    head = prev if entries else None
    report = ChainReport(
        tenant=tenant, ok=True, length=len(entries), signer=expect_signer,
        legacy_receipts=legacy_receipts, head=head, unchained_receipts=unchained_receipts,
    )
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
        report.mismatches = reconcile(entries, stored)
        if report.mismatches:
            report.ok = False

    # Receipts the chain never recorded. Up to the number that already existed
    # when the chain started, that is history the chain cannot speak for;
    # beyond it, rows were written around the chain.
    if unchained_receipts > legacy_receipts:
        inserted = unchained_receipts - legacy_receipts
        report.mismatches.append(
            f"{inserted} receipt(s) exist that the chain never recorded"
        )
        report.ok = False
    if legacy_receipts:
        report.notes.append(
            f"{legacy_receipts} receipt(s) predate the chain and are outside it "
            f"(this baseline is bound into the chain's genesis and cannot be raised "
            f"once the chain has an entry)"
        )
    return report
