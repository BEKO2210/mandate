"""v0.7.0 receipt-chain gates G158-G175.

Signatures proved who wrote each receipt. They proved nothing about the set of
receipts: an operator with database access could delete a row, roll a state
back, or insert one, and every remaining signature still verified.

These gates are written as the attacks, not as the feature. Each one does to
the database what an operator with a SQL prompt would do, then asks the
verifier. A gate that only checked "the chain links to itself" would have
passed against a database with rows deleted out of it — that is exactly what
happened on the first attempt here, and G165-G168 exist because of it.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest

from mandate import chain as chainlib
from mandate.crypto import KeyPair, utcnow
from mandate.engine import Engine
from mandate.executor import ExecutionResult
from mandate.ledger import Ledger, StorageError
from mandate.routes import Route, RouteRegistry


class _Upstream:
    def forward(self, route, method, path, body, idempotency_key):
        return ExecutionResult("EXECUTED", 200, 3, "sha256:response", None)


def _world(tmp_path, calls: int = 3, tenant: str = "default"):
    """A ledger with `calls` receipts driven all the way to EXECUTED."""
    db = tmp_path / "m.sqlite"
    engine = Engine(
        ledger=Ledger(db),
        executor=_Upstream(),
        routes=RouteRegistry([Route(
            audience="mandate://local", base_url="https://upstream.example",
            allowed_methods=("POST",), allowed_paths=("/do",), tenant=tenant,
        )]),
    )
    person, pkp = engine.register_principal("Belkis", tenant=tenant)
    agent, akp = engine.register_agent("Bot", person.did, "Mandate", "t", tenant=tenant)
    grant = engine.issue_grant(
        person, pkp, agent, organization="Aslani GmbH", purpose="p",
        scopes=["x.do"], not_after=utcnow() + timedelta(days=1), tenant=tenant,
    )
    ids = []
    for i in range(calls):
        receipt = engine.propose(akp, grant["id"], "x.do", summary=f"call {i}", tenant=tenant)
        engine.execute(receipt["id"], idempotency_key=f"idem-{i}", tenant=tenant)
        ids.append(receipt["id"])
    assert engine.verify_chain(tenant).ok, "the world must start clean"
    return engine, db, ids, {"agent": akp, "grant": grant["id"]}


def _sql(db, statement, *params):
    con = sqlite3.connect(db)
    try:
        con.execute(statement, params)
        con.commit()
    finally:
        con.close()


# --- The chain itself ------------------------------------------------------


def test_g158_every_state_a_receipt_reaches_is_recorded_once(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=2)
    with engine.ledger.tx() as tx:
        entries = tx.chain_entries("default")

    assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))
    # PROPOSED-to-AUTHORIZED, EXECUTING, then the terminal state, per receipt.
    for receipt_id in ids:
        outcomes = [e["outcome"] for e in entries if e["receipt_id"] == receipt_id]
        assert outcomes == ["AUTHORIZED", "EXECUTING", "EXECUTED"], outcomes


def test_g159_each_entry_commits_to_the_one_before_it(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=2)
    with engine.ledger.tx() as tx:
        entries = tx.chain_entries("default")

    assert entries[0]["prev"] == chainlib.genesis("default")
    for earlier, later in zip(entries, entries[1:]):
        assert later["prev"] == earlier["entry_hash"]


def test_g160_an_entry_cannot_be_edited_without_breaking_its_hash():
    kp = KeyPair.generate()
    entry = chainlib.sign_entry(kp, chainlib.entry_body(
        seq=1, tenant="default", prev=chainlib.genesis("default"),
        receipt_id="rcpt_1", outcome="AUTHORIZED",
        body_hash="sha256:abc", recorded_at="2026-09-22T10:00:00Z",
    ))
    ok = chainlib.check_entry(
        entry, expect_seq=1, expect_prev=chainlib.genesis("default"), expect_tenant="default"
    )
    assert ok is None

    for field, value in [
        ("outcome", "EXECUTED"), ("receipt_id", "rcpt_other"),
        ("body_hash", "sha256:def"), ("recorded_at", "2020-01-01T00:00:00Z"),
    ]:
        tampered = {**entry, field: value}
        assert chainlib.check_entry(
            tampered, expect_seq=1, expect_prev=chainlib.genesis("default"),
            expect_tenant="default",
        ) == "entry_hash does not match the entry's contents"


def test_g161_deleting_an_entry_breaks_the_chain_where_it_was(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=3)
    _sql(db, "DELETE FROM chain WHERE seq=4")

    report = engine.verify_chain()
    assert not report.ok
    assert report.broken_at == 4


def test_g162_reordering_entries_breaks_the_chain(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=3)
    _sql(db, "UPDATE chain SET seq=99 WHERE seq=5")

    report = engine.verify_chain()
    assert not report.ok
    assert report.broken_at == 5


def test_g163_an_entry_from_another_tenant_cannot_be_spliced_in():
    """Genesis binds the tenant, so a stolen entry carries where it came from."""
    assert chainlib.genesis("acme") != chainlib.genesis("default")

    kp = KeyPair.generate()
    theirs = chainlib.sign_entry(kp, chainlib.entry_body(
        seq=1, tenant="acme", prev=chainlib.genesis("acme"), receipt_id="rcpt_1",
        outcome="AUTHORIZED", body_hash="sha256:abc", recorded_at="2026-09-22T10:00:00Z",
    ))
    problem = chainlib.check_entry(
        theirs, expect_seq=1, expect_prev=chainlib.genesis("default"), expect_tenant="default"
    )
    assert problem is not None and "tenant" in problem


def test_g164_a_real_entry_cannot_be_replayed_at_another_position(tmp_path):
    """Correctly signed is not the same as belonging here."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    with engine.ledger.tx() as tx:
        entry = tx.chain_entries("default")[0]

    con = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                """INSERT INTO chain(tenant, seq, receipt_id, outcome, body_hash, prev,
                   entry_hash, recorded_at, signer, signature)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("default", 999, entry["receipt_id"], entry["outcome"], entry["body_hash"],
                 entry["prev"], entry["entry_hash"], entry["recorded_at"],
                 entry["signer"], entry["signature"]),
            )
    finally:
        con.close()


def test_g165_deleting_a_receipt_row_is_caught(tmp_path):
    """The attack the first version of this feature missed entirely: the chain
    verified itself perfectly while the rows it commits to were gone."""
    engine, db, ids, _ = _world(tmp_path, calls=3)
    _sql(db, "DELETE FROM receipts WHERE id=?", ids[1])

    report = engine.verify_chain()
    assert not report.ok
    assert any("no longer in the database" in m for m in report.mismatches)
    assert ids[1] in report.mismatches[0]


def test_g166_rolling_a_receipt_state_back_is_caught(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=2)
    _sql(db, "UPDATE receipts SET state='AUTHORIZED' WHERE id=?", ids[0])

    report = engine.verify_chain()
    assert not report.ok
    assert any("the chain's last entry" in m for m in report.mismatches)


def test_g167_editing_a_receipt_body_is_caught_but_reformatting_is_not(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=2)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    body = json.loads(con.execute(
        "SELECT body FROM receipts WHERE id=?", (ids[0],)
    ).fetchone()["body"])
    con.close()

    # Re-serialising the same content is not tampering: the hash is canonical.
    _sql(db, "UPDATE receipts SET body=? WHERE id=?",
         json.dumps(body, indent=4, sort_keys=False), ids[0])
    assert engine.verify_chain().ok, "whitespace is not a finding"

    # Changing what it says is.
    body["intent"]["summary"] = "something else entirely"
    _sql(db, "UPDATE receipts SET body=? WHERE id=?", json.dumps(body), ids[0])
    report = engine.verify_chain()
    assert not report.ok
    assert any("contents changed after it was chained" in m for m in report.mismatches)


def test_g168_a_receipt_inserted_around_the_chain_is_caught(tmp_path):
    engine, db, ids, _ = _world(tmp_path, calls=2)
    _sql(
        db,
        """INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce,
           action, state, body, tenant)
           SELECT 'rcpt_forged', grant_id, agent_did, principal_did, audience, 'nonce-x',
           action, state, body, tenant FROM receipts LIMIT 1""",
    )

    report = engine.verify_chain()
    assert not report.ok
    assert any("the chain never recorded" in m for m in report.mismatches)


def test_g169_truncation_is_invisible_without_a_head_and_provable_with_one(tmp_path):
    """The honest limit, stated as a gate so it cannot be quietly forgotten."""
    engine, db, ids, _ = _world(tmp_path, calls=3)
    kept = engine.chain_head()["entry_hash"]

    # Drop the last receipt and every entry about it: a clean prefix.
    _sql(db, "DELETE FROM chain WHERE receipt_id=?", ids[2])
    _sql(db, "DELETE FROM receipts WHERE id=?", ids[2])

    blind = engine.verify_chain()
    assert blind.ok, "a prefix of a valid chain is a valid chain"

    witnessed = engine.verify_chain(expect_head=kept)
    assert not witnessed.ok
    assert "missing" in (witnessed.reason or "")


# --- The write path --------------------------------------------------------


def test_g170_a_receipt_cannot_be_written_without_a_chain_entry(tmp_path):
    """Make the gap impossible rather than documented: the ledger refuses."""
    engine, db, ids, _ = _world(tmp_path, calls=1)

    with engine.ledger.tx() as tx:
        with pytest.raises(TypeError):
            tx.insert_receipt({"id": "rcpt_x"})  # chain is required, not optional
        # Reported whether or not the transition asked for is itself legal.
        with pytest.raises(StorageError, match="must be chained"):
            tx.cas_state(ids[0], "AUTHORIZED", "EXECUTING", {"x": 1})
        with pytest.raises(StorageError, match="must be chained"):
            tx.cas_state(ids[0], "EXECUTED", "EXECUTED", {"x": 1})

    assert engine.verify_chain().ok


def test_g171_a_lost_state_race_appends_nothing(tmp_path):
    """The entry goes in after the CAS wins, so a receipt that did not move
    leaves no record of having moved."""
    engine, db, ids, _ = _world(tmp_path, calls=1)
    before = engine.chain_head()["seq"]

    with engine.ledger.tx() as tx:
        moved = tx.cas_state(
            ids[0], "AUTHORIZED", "EXECUTING", {"x": 1},
            chain=engine._chain(tx, "default", ids[0], "EXECUTING", {"x": 1}),
        )
    assert moved is False, "the receipt is EXECUTED, not AUTHORIZED"
    assert engine.chain_head()["seq"] == before
    assert engine.verify_chain().ok


def test_g172_each_tenant_has_its_own_chain(tmp_path):
    """One tenant's activity must not advance — or be visible in — another's."""
    engine, db, ids, ctx = _world(tmp_path, calls=2, tenant="acme")

    with engine.ledger.tx() as tx:
        assert tx.chain_entries("acme")
        assert tx.chain_entries("default") == []
        assert tx.chain_head("default") is None
    assert engine.verify_chain("acme").ok
    assert engine.verify_chain("default").ok
    assert engine.verify_chain("default").length == 0


def test_g173_receipts_that_predate_the_chain_are_a_note_not_a_finding(tmp_path):
    """Upgrading must not accuse the operator of tampering with old rows."""
    report = chainlib.verify_chain(
        [], "default", unchained_receipts=7, legacy_receipts=7
    )
    assert report.ok
    assert report.notes and "predate the chain" in report.notes[0]

    # One more than the chain started with means a row was written around it.
    worse = chainlib.verify_chain(
        [], "default", unchained_receipts=8, legacy_receipts=7
    )
    assert not worse.ok
    assert "1 receipt(s) exist that the chain never recorded" in worse.mismatches[0]


def test_g174_verification_needs_no_key_and_still_catches_a_partial_reseal(tmp_path):
    """An auditor holds no enforcer key. Requiring one made every healthy chain
    report as BROKEN — a verifier that cries wolf is worse than none.

    Without an expected signer the walk still pins every entry to the signer
    the first one names, so a chain re-signed only in part is caught.
    """
    engine, db, ids, _ = _world(tmp_path, calls=2)
    engine.ledger.close()

    auditor = Engine(ledger=Ledger(db))  # a key of its own, not the enforcer's
    assert auditor.enforcer_did != auditor.verify_chain().signer
    report = auditor.verify_chain()
    assert report.ok, report.summary()
    assert report.signer and report.signer.startswith("did:key:")

    # Naming the wrong enforcer is still a finding.
    wrong = auditor.verify_chain(expect_signer=auditor.enforcer_did)
    assert not wrong.ok and wrong.broken_at == 1

    # Re-signing part of the chain with another key is caught with no key at all.
    other = KeyPair.generate()
    with auditor.ledger.tx() as tx:
        entries = tx.chain_entries("default")
    resealed = chainlib.sign_entry(other, {
        k: entries[-1][k] for k in chainlib.ENTRY_FIELDS
    })
    _sql(
        db,
        "UPDATE chain SET entry_hash=?, signer=?, signature=? WHERE seq=?",
        resealed["entry_hash"], resealed["signer"], resealed["signature"], entries[-1]["seq"],
    )
    auditor.ledger.close()
    again = Engine(ledger=Ledger(db)).verify_chain()
    assert not again.ok
    assert again.broken_at == entries[-1]["seq"]


def test_g175_an_enforcer_that_cannot_sign_refuses_instead_of_escaping(tmp_path):
    """`submit_intent` now signs twice — the receipt and its chain entry — so a
    SigningError escaping it as itself, past callers that handle MandateError,
    became likelier. It was already possible before this release."""
    from mandate.engine import MandateError
    from mandate.signing import SigningError

    engine, db, ids, ctx = _world(tmp_path, calls=1)

    class Dead:
        name = "dead"

        def __init__(self, inner):
            self._inner = inner

        def did(self):
            return self._inner.did()

        def sign(self, payload):
            raise SigningError("kms unreachable")

        def sign_hex(self, payload):
            return self.sign(payload).hex()

    engine.enforcer = Dead(engine.enforcer)
    with pytest.raises(MandateError, match="could not be signed"):
        engine.propose(ctx["agent"], ctx["grant"], "x.do", summary="after the key died")
