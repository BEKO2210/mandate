"""v0.7.0 receipt-chain gates G158-G201.

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
from mandate.crypto import KeyPair, utcnow, verify_object
from mandate.engine import Engine, MandateError
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


def test_g176_balancing_the_receipt_count_does_not_hide_a_swap(tmp_path):
    """The count of unchained receipts is a secondary net, so the obvious
    attack on it is to keep it level: remove one receipt, add another.

    Each variant is checked rather than argued, because "the other check will
    catch it" is exactly the reasoning that left the first version of this
    feature catching nothing.
    """
    fake = (
        "INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce,"
        " action, state, body, tenant)"
        " SELECT 'rcpt_fake', grant_id, agent_did, principal_did, audience, 'nonce-z',"
        " action, state, body, tenant FROM receipts LIMIT 1"
    )

    # 1. Swap a mid-chain receipt for a fake: the chain still names the real one.
    engine, db, ids, _ = _world(tmp_path / "a", calls=4)
    _sql(db, "DELETE FROM receipts WHERE id=?", ids[1])
    _sql(db, fake)
    report = engine.verify_chain()
    assert not report.ok
    assert any("no longer in the database" in m for m in report.mismatches)

    # 2. Remove its chain entries too: the links break where they were.
    engine, db, ids, _ = _world(tmp_path / "b", calls=4)
    _sql(db, "DELETE FROM chain WHERE receipt_id=?", ids[1])
    _sql(db, "DELETE FROM receipts WHERE id=?", ids[1])
    report = engine.verify_chain()
    assert not report.ok
    # Named, not merely counted: "not ok" is satisfied by any finding at all,
    # including one that has nothing to do with the links this variant claims
    # to break. Review found this shape in G188 and here.
    assert report.broken_at == 4, report
    assert "expected seq 4" in (report.reason or ""), report

    # 3. Do it at the tail, where the links survive: the count catches it.
    engine, db, ids, _ = _world(tmp_path / "c", calls=4)
    _sql(db, "DELETE FROM chain WHERE receipt_id=?", ids[3])
    _sql(db, "DELETE FROM receipts WHERE id=?", ids[3])
    _sql(db, fake)
    report = engine.verify_chain()
    assert not report.ok
    assert any("never recorded" in m for m in report.mismatches)

    # 4. Keep the real id and forge its contents, dropping its entries.
    engine, db, ids, _ = _world(tmp_path / "d", calls=4)
    _sql(db, "DELETE FROM chain WHERE receipt_id=?", ids[3])
    _sql(db, "UPDATE receipts SET body=json_set(body,'$.intent.summary','forged') WHERE id=?",
         ids[3])
    report = engine.verify_chain()
    assert not report.ok
    assert any("never recorded" in m for m in report.mismatches)


# --- What independent review found ------------------------------------------


def test_g177_the_legacy_baseline_cannot_be_raised_to_licence_inserts(tmp_path):
    """The baseline that bounds unchained receipts lives in `meta`, where an
    operator can write. Raising it by one permitted one forged receipt, with
    no key needed — a complete bypass of G168 and of G176's tail variants.

    Genesis now binds the baseline, so entry 1 stops matching the moment it
    changes.
    """
    engine, db, ids, _ = _world(tmp_path, calls=3)
    _sql(
        db,
        """INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce,
           action, state, body, tenant)
           SELECT 'rcpt_forged', grant_id, agent_did, principal_did, audience, 'nonce-z',
           action, state, body, tenant FROM receipts LIMIT 1""",
    )
    assert not engine.verify_chain().ok, "the insert alone is caught"

    _sql(db, "INSERT OR REPLACE INTO meta(key, value) VALUES('chain_legacy', ?)",
         json.dumps({"default": 1}))
    report = engine.verify_chain()
    assert not report.ok, "raising the baseline must not clear the finding"
    assert report.broken_at == 1
    assert "prev does not match" in (report.reason or "")


def test_g178_genesis_binds_the_baseline_as_well_as_the_tenant():
    assert chainlib.genesis("default", 0) != chainlib.genesis("default", 1)
    assert chainlib.genesis("acme", 3) != chainlib.genesis("default", 3)


def test_g179_a_duplicate_json_member_is_not_a_free_edit(tmp_path):
    """`json.loads` keeps the last of a repeated key, so prepending
    `"outcome": "DENIED"` changes the stored bytes while the canonical hash
    stays put. A document two parsers disagree about is already tampered with.
    """
    engine, db, ids, _ = _world(tmp_path, calls=1)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    raw = con.execute("SELECT body FROM receipts WHERE id=?", (ids[0],)).fetchone()["body"]
    con.close()

    doctored = '{"outcome": "DENIED", ' + raw[1:]
    assert json.loads(doctored)["outcome"] != "DENIED", "last member wins in this parser"
    _sql(db, "UPDATE receipts SET body=? WHERE id=?", doctored, ids[0])

    report = engine.verify_chain()
    assert not report.ok
    assert any("duplicate member" in m for m in report.mismatches)

    with pytest.raises(ValueError, match="duplicate member"):
        chainlib.loads_strict('{"a": 1, "a": 2}')
    with pytest.raises(ValueError, match="duplicate member"):
        chainlib.loads_strict('{"outer": {"a": 1, "a": 2}}')


def test_g180_concurrent_migration_cannot_inflate_the_baseline(tmp_path):
    """Two processes could both see schema 3, one finish and write a chained
    receipt, and the other count that receipt into the baseline."""
    import threading

    from mandate.crypto import utcnow as now

    db = tmp_path / "old.sqlite"
    engine = Engine(ledger=Ledger(db))
    person, pkp = engine.register_principal("Belkis")
    agent, akp = engine.register_agent("Bot", person.did, "Mandate", "t")
    grant = engine.issue_grant(
        person, pkp, agent, organization="A", purpose="p", scopes=["x.do"],
        not_after=now() + timedelta(days=1),
    )
    for i in range(3):
        engine.propose(akp, grant["id"], "x.do", summary=f"s{i}")
    engine.ledger.close()

    # Rewind it to a v0.6 database.
    _sql(db, "DROP TABLE chain")
    _sql(db, "DELETE FROM meta WHERE key IN ('chain_started_at','chain_legacy')")
    _sql(db, "UPDATE meta SET value='3' WHERE key='schema_version'")

    opened, errors = [], []

    def migrate():
        try:
            opened.append(Ledger(db))
        except Exception as exc:  # noqa: BLE001 - the point of the gate
            errors.append(exc)

    threads = [threading.Thread(target=migrate) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    baseline = con.execute("SELECT value FROM meta WHERE key='chain_legacy'").fetchone()
    con.close()
    for ledger in opened:
        ledger.close()
    assert json.loads(baseline["value"]) == {"default": 3}, "one snapshot, taken once"


def test_g181_a_tenant_with_no_chain_is_still_verified(tmp_path):
    """The one tenant worth looking at is the one with no chain entries.

    Enumerating tenants from the `chain` table alone skips exactly the shape a
    receipt written around the chain has. An operator could open a fresh
    tenant, insert a forged receipt into it, and the verifier would walk every
    *other* tenant, find them intact and exit 0.
    """
    engine, db, ids, _ = _world(tmp_path, calls=2)
    engine.ledger.close()

    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    row = dict(con.execute("SELECT * FROM receipts LIMIT 1").fetchone())
    con.close()
    row["id"] = "rcpt_forged_in_a_new_tenant"
    row["tenant"] = "shadow"
    _sql(
        db,
        f"INSERT INTO receipts ({','.join(row)}) VALUES ({','.join('?' * len(row))})",
        *row.values(),
    )

    engine = Engine(ledger=Ledger(db))
    try:
        with engine.ledger.tx() as tx:
            tenants = tx.chain_tenants()
        assert "shadow" in tenants, "a tenant with receipts is a tenant to verify"
        report = engine.verify_chain("shadow")
        assert not report.ok
        assert any("never recorded" in m for m in report.mismatches), report.mismatches
    finally:
        engine.ledger.close()


def test_g182_a_fabricated_receipt_is_caught_by_its_own_proof(tmp_path):
    """The count is not the last line of defence — the receipt's signature is.

    An operator who licences an unchained insert by raising the baseline for a
    tenant whose chain is still empty defeats every count-based check. What
    they cannot do without the enforcer key is make the row's own proof
    verify, and verifying it needs no secret: the DID is in the proof.
    """
    engine, db, ids, _ = _world(tmp_path, calls=2)
    engine.ledger.close()

    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    row = dict(con.execute("SELECT * FROM receipts LIMIT 1").fetchone())
    con.close()

    body = json.loads(row["body"])
    body["id"] = row["id"] = "rcpt_fabricated"
    body["summary"] = "pay the operator"
    row["body"] = json.dumps(body)
    row["tenant"] = "shadow"
    _sql(
        db,
        f"INSERT INTO receipts ({','.join(row)}) VALUES ({','.join('?' * len(row))})",
        *row.values(),
    )
    # ... and licence it, which the count check has no way to refuse.
    _sql(
        db,
        "UPDATE meta SET value=? WHERE key='chain_legacy'",
        json.dumps({"default": 0, "shadow": 1}),
    )

    engine = Engine(ledger=Ledger(db))
    try:
        report = engine.verify_chain("shadow")
        assert not report.ok, "a receipt nobody signed is not evidence"
        assert any("does not carry a signature" in m for m in report.mismatches), report
        assert engine.verify_chain("default").ok, "and no false alarm next door"
    finally:
        engine.ledger.close()


def test_g183_a_real_receipt_never_trips_the_proof_check(tmp_path):
    """The other half of G182: a verifier that cries wolf is worse than none.

    Key rotation must not turn healthy receipts into findings either, so the
    check is against the DID the proof itself names, not against a current one.
    """
    engine, db, ids, _ = _world(tmp_path, calls=3)
    try:
        with engine.ledger.tx() as tx:
            digests = tx.receipt_digests("default")
        assert digests, "the world must have receipts"
        assert all(d["proof_ok"] for d in digests.values()), digests
        assert engine.verify_chain("default").ok
    finally:
        engine.ledger.close()


def test_g184_a_poisoned_receipt_costs_one_finding_not_the_run(tmp_path):
    """`"\\ud800"` is a legal JSON escape and an illegal Unicode string.

    It parsed, and then canonicalisation raised on the way out — after the
    error boundary. The verifier died mid-run with an empty report, so one
    poisoned field blinded it to every *other* receipt as well. That is worse
    than the edit it hides: a crash is a verifier that says nothing.
    """
    import re

    engine, db, ids, _ = _world(tmp_path, calls=3)
    engine.ledger.close()

    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    raw = con.execute("SELECT body FROM receipts WHERE id=?", (ids[0],)).fetchone()["body"]
    con.close()
    poisoned = re.sub(r'"summary":\s*"[^"]*"', r'"summary":"\\ud800"', raw, count=1)
    assert poisoned != raw, "the fixture must contain the field this attacks"
    _sql(db, "UPDATE receipts SET body=? WHERE id=?", poisoned, ids[0])
    # A second, ordinary tampering that the crash used to hide.
    _sql(db, "UPDATE receipts SET state='DENIED' WHERE id=?", ids[1])

    engine = Engine(ledger=Ledger(db))
    try:
        report = engine.verify_chain("default")
    finally:
        engine.ledger.close()
    assert not report.ok
    assert any("not valid Unicode" in m for m in report.mismatches), report.mismatches
    assert any("DENIED" in m for m in report.mismatches), (
        "the poisoned row must not cost the findings about the others"
    )


def test_g185_json_that_no_conforming_parser_reads_back_is_refused():
    """NaN and Infinity are Python's extensions to JSON, not JSON."""
    for raw in ('{"n": NaN}', '{"n": Infinity}', '{"n": -Infinity}'):
        with pytest.raises(chainlib.UnusableBody):
            chainlib.loads_strict(raw)
    with pytest.raises(chainlib.UnusableBody):
        chainlib.loads_strict('{"text": "\\ud800"}')
    with pytest.raises(chainlib.UnusableBody):
        chainlib.loads_strict('{"outer": {"text": "\\udc00"}}')
    # A paired surrogate is an ordinary character and must still be readable.
    assert chainlib.loads_strict('{"text": "\\ud83d\\ude00"}') == {"text": "\U0001f600"}


def _poisoned_world(tmp_path, mutate):
    """One receipt poisoned, and a second one tampered with ordinarily.

    The second is the point. A verifier that dies on the first says nothing
    about the rest of the database, so every one of these gates asserts that
    the *ordinary* finding survives the poisoned row.
    """
    engine, db, ids, _ = _world(tmp_path, calls=3)
    engine.ledger.close()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    raw = con.execute("SELECT body FROM receipts WHERE id=?", (ids[0],)).fetchone()["body"]
    con.close()
    _sql(db, "UPDATE receipts SET body=? WHERE id=?", mutate(raw), ids[0])
    _sql(db, "UPDATE receipts SET state='DENIED' WHERE id=?", ids[1])

    engine = Engine(ledger=Ledger(db))
    try:
        return engine.verify_chain("default")
    finally:
        engine.ledger.close()


def test_g186_a_proof_that_is_not_an_object_is_answered_not_raised(tmp_path):
    """`proof.get` on a list raises AttributeError, which escaped the boundary.

    It emptied the whole report, and it did the same to `mandate verify` on a
    file — a traceback where INVALID belonged. Hostile input reaching a
    verifier is the normal case, not the exceptional one.
    """
    for hostile in ([], "nope", 7, {"verificationMethod": 7},
                    {"verificationMethod": "did:key:z6Mk", "proofValue": []},
                    # A *string* that is not a DID reaches did_to_public_bytes,
                    # which raises before `verify` has a try block of its own.
                    # Review found this one after the first fix: checking each
                    # field encodes a guess about what malformed input can do.
                    {"verificationMethod": "not-a-did", "proofValue": ""},
                    {"verificationMethod": "", "proofValue": ""},
                    {"verificationMethod": "did:web:example.com", "proofValue": ""},
                    {"verificationMethod": "did:key:zZZZZ", "proofValue": ""}):
        assert verify_object({"id": "x", "proof": hostile}) is False, hostile
    assert verify_object(["not", "a", "dict"]) is False
    # A direct caller can make canonicalisation itself raise.
    assert verify_object({"id": "x", 1: "non-string key",
                          "proof": {"verificationMethod": "did:key:z6Mk",
                                    "proofValue": ""}}) is False

    def mutate(raw):
        """Replace the proof with a list, so `.get` has nothing to answer."""
        body = json.loads(raw)
        body["proof"] = []
        return json.dumps(body)

    report = _poisoned_world(tmp_path, mutate)
    assert not report.ok
    assert any("DENIED" in m for m in report.mismatches), (
        "the poisoned row must not cost the finding about the other receipt"
    )


def test_g187_a_deeply_nested_body_is_a_finding_not_a_crash(tmp_path):
    """RecursionError is neither ValueError nor TypeError, so it escaped too.

    An operator writes bytes, not Python objects: the nesting goes in as text
    and the parser blows the stack on the way in.

    The depth is far past any interpreter's limit on purpose. How deep is too
    deep is an interpreter detail — 3.11 gives up at 1000 and 3.13 parses
    20000 — so the gate pins the behaviour, never the threshold: a body the
    parser cannot handle is reported, and the run survives it.
    """
    deep = '{"a":' * 25000 + "1" + "}" * 25000

    def mutate(raw):
        """Append nesting past any interpreter's limit, as raw text."""
        return raw[:-1] + ',"pad":' + deep + "}"

    report = _poisoned_world(tmp_path, mutate)
    assert not report.ok
    assert any("cannot be read" in m for m in report.mismatches), report.mismatches
    assert any("DENIED" in m for m in report.mismatches), (
        "the poisoned row must not cost the finding about the other receipt"
    )


def test_g188_a_body_the_interpreter_can_parse_is_still_reconciled(tmp_path):
    """The other half: depth that parses must not become a free edit.

    3.13 reads 3000-deep nesting happily. That body is still a changed body,
    so the canonical hash has to catch it — otherwise a gate written around
    one interpreter's stack limit would leave a hole on another's.
    """
    def mutate(raw):
        """Append nesting every interpreter parses, so the hash must catch it."""
        return raw[:-1] + ',"pad":' + ('{"a":' * 500 + "1" + "}" * 500) + "}"

    report = _poisoned_world(tmp_path, mutate)
    assert not report.ok
    # The claim is that the *changed body* is caught. Asserting "not ok" and
    # the unrelated rollback would be satisfied by a verifier that ignored the
    # edit entirely — the same assertion-shape defect G189 had.
    assert any("contents changed after it was chained" in m
               for m in report.mismatches), report.mismatches
    assert any("DENIED" in m for m in report.mismatches), report.mismatches


def test_g189_the_file_verifier_says_invalid_instead_of_crashing(tmp_path, capsys):
    """`mandate verify` is the command an auditor runs on a file they were sent.

    A traceback there is not a verdict. The file is hostile input by
    definition — it is the thing being questioned — so every malformed shape
    has to come back as INVALID with a non-zero exit, not as a stack trace
    that says nothing about whether the receipt is genuine.

    The printed word is asserted, not only the exit code. An earlier version
    of this gate checked the status alone and would have passed a command
    that printed VALID and returned 1 — a test that proves less than it looks
    like it proves, which in evidence code is the same failure as a verifier
    that says nothing. Review caught it.
    """
    from mandate.cli import main

    hostile = [
        {"id": "x", "proof": {"verificationMethod": "not-a-did", "proofValue": ""}},
        {"id": "x", "proof": {"verificationMethod": "did:web:example.com",
                              "proofValue": ""}},
        {"id": "x", "proof": []},
        {"id": "x"},
    ]
    for i, obj in enumerate(hostile):
        path = tmp_path / f"hostile-{i}.json"
        path.write_text(json.dumps(obj), encoding="utf-8")
        assert main(["verify", str(path)]) == 1, obj
        captured = capsys.readouterr()
        assert captured.out == "INVALID\n", obj
        # A caught traceback on stderr is still a traceback. The verdict is
        # the whole output, not the part that happens to be on stdout.
        assert captured.err == "", obj

    # The other half: a genuine receipt must still come back VALID and 0, or
    # the gate above is satisfied by a command that condemns everything.
    #
    # It is a receipt from the pipeline, not a hand-built dict handed to
    # `sign_object`. `sign_object` signs any dictionary, so signing one here
    # would prove that a valid signature verifies — true, and not the claim.
    # The claim is that what this system actually produces still passes.
    # Review caught the substitution.
    engine, db, ids, _ = _world(tmp_path / "genuine-world", calls=1)
    engine.ledger.close()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    stored = con.execute("SELECT body FROM receipts WHERE id=?", (ids[0],)).fetchone()
    con.close()
    good = tmp_path / "genuine.json"
    good.write_text(stored["body"], encoding="utf-8")
    assert main(["verify", str(good)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "VALID\n"
    assert captured.err == ""


# --- Closing the three residuals --------------------------------------------


def _forge_history(engine, outcomes, receipt_id="rcpt_forged"):
    """Append entries with the chain's real key — the only interesting case.

    A forgery signed with some other key is caught by the signature check and
    proves nothing about what this gate is for. An earlier version of this
    helper used a fresh engine, whose ephemeral key made the whole attack
    bounce off the wrong wall.
    """
    with engine.ledger.tx() as tx:
        for outcome in outcomes:
            head = tx.chain_head("default")
            body = chainlib.entry_body(
                seq=head["seq"] + 1, tenant="default", prev=head["entry_hash"],
                receipt_id=receipt_id, outcome=outcome,
                body_hash="sha256:" + "0" * 64, recorded_at="2026-09-22T20:00:00Z",
            )
            tx.append_chain(chainlib.sign_entry(engine.enforcer, body))


def test_g190_a_receipt_cannot_enter_the_chain_already_finished(tmp_path):
    """Evaluation happens before the first write, so a receipt may be created
    already denied or already authorized — never already executed."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    try:
        _forge_history(engine, ["EXECUTED"])
        report = engine.verify_chain()
        assert not report.ok
        assert any("already EXECUTED" in m for m in report.mismatches), report.mismatches
    finally:
        engine.ledger.close()


def test_g191_the_states_a_receipt_passed_through_must_be_a_legal_road(tmp_path):
    """Reconciliation compares against the *last* entry and says nothing about
    how the receipt got there. Skipping authorization, or walking backwards,
    both produce a destination that looks fine."""
    for outcomes, forbidden in (
        (["PROPOSED", "EXECUTED"], "PROPOSED -> EXECUTED"),
        (["AUTHORIZED", "PROPOSED"], "AUTHORIZED -> PROPOSED"),
        (["PROPOSED", "AUTHORIZED", "EXECUTING", "EXECUTED", "EXECUTING"],
         "EXECUTED -> EXECUTING"),
    ):
        engine, db, ids, _ = _world(tmp_path / forbidden[:9].strip(), calls=2)
        try:
            _forge_history(engine, outcomes)
            report = engine.verify_chain()
            assert not report.ok
            assert any(forbidden in m for m in report.mismatches), (outcomes, report.mismatches)
        finally:
            engine.ledger.close()


def test_g192_a_legal_road_is_not_a_finding(tmp_path):
    """The other half, and the one that matters: a check that condemns every
    history is a check that establishes nothing. This branch has already
    shipped one verifier that cried wolf."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    try:
        _forge_history(engine, ["PROPOSED", "AUTHORIZED", "EXECUTING", "EXECUTED"])
        report = engine.verify_chain()
        walked = [m for m in report.mismatches if "state machine does not allow" in m]
        assert not walked, walked
        assert not any("already" in m for m in report.mismatches), report.mismatches
    finally:
        engine.ledger.close()


def test_g193_an_anchor_makes_truncation_visible(tmp_path):
    """A prefix of a valid chain is a valid chain, so nothing inside a database
    can speak for what was cut off its end. Until this, the codebase said so
    and left the reader to do something about it."""
    engine, db, ids, _ = _world(tmp_path, calls=4)
    try:
        anchor = engine.anchor_chain()
        assert anchor and anchor["seq"] > 0
    finally:
        engine.ledger.close()

    # An operator cutting the tail off takes the receipts with it — leaving
    # them behind is caught by the count, and would make this gate pass for
    # the wrong reason.
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    doomed = [r["receipt_id"] for r in
              con.execute("SELECT DISTINCT receipt_id FROM chain WHERE seq > ?",
                          (anchor["seq"] - 3,))]
    con.close()
    _sql(db, "DELETE FROM chain WHERE seq > ?", anchor["seq"] - 3)
    for receipt_id in doomed:
        _sql(db, "DELETE FROM receipts WHERE id=?", receipt_id)

    engine = Engine(ledger=Ledger(db))
    try:
        blind = engine.verify_chain()
        assert blind.ok, (
            "a truncated chain is internally consistent — that is the problem: "
            f"{blind.mismatches}"
        )

        seen = engine.verify_chain(anchors=[anchor])
        assert not seen.ok
        assert any("anchor recorded seq" in m for m in seen.mismatches), seen.mismatches
    finally:
        engine.ledger.close()


def test_g194_an_anchor_also_catches_a_rewrite_beneath_it(tmp_path):
    """Truncation is the headline; the same record catches history edited
    under a head somebody already wrote down."""
    engine, db, ids, _ = _world(tmp_path, calls=3)
    try:
        anchor = engine.anchor_chain()

        # Re-signed properly, so the walk has nothing to object to: the head is
        # the one entry that can be rewritten without breaking any `prev`.
        # Only the anchor knows it used to say something else.
        with engine.ledger.tx() as tx:
            rows = tx.chain_entries("default")
        head = rows[-1]
        body = {k: head[k] for k in chainlib.ENTRY_FIELDS}
        body["outcome"] = "DENIED"
        resigned = chainlib.sign_entry(engine.enforcer, body)
        _sql(db, "UPDATE chain SET outcome=?, entry_hash=?, signature=? WHERE seq=?",
             "DENIED", resigned["entry_hash"], resigned["signature"], head["seq"])

        blind = engine.verify_chain()
        assert not any("anchor" in m for m in blind.mismatches), blind.mismatches

        report = engine.verify_chain(anchors=[anchor])
        assert not report.ok
        assert any("history was rewritten under it" in m for m in report.mismatches), report
    finally:
        engine.ledger.close()


def test_g195_a_rotation_is_an_act_of_the_key_being_replaced(tmp_path):
    """Whoever steals the current key must not be able to declare themselves
    the signer — otherwise a rotation record is a gift to the thief."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    thief = KeyPair.generate()
    try:
        with engine.ledger.tx() as tx:
            head = tx.chain_head("default")
            body = chainlib.rotation_body(
                seq=head["seq"] + 1, tenant="default", prev=head["entry_hash"],
                new_signer=thief.did(), recorded_at="2026-09-22T20:00:00Z",
            )
            tx.append_chain(chainlib.sign_entry(thief, body))
        report = engine.verify_chain()
        assert not report.ok
        assert "not by" in (report.reason or ""), report
    finally:
        engine.ledger.close()


def test_g196_a_chain_survives_a_rotation_and_binds_what_came_before(tmp_path):
    """Pinned to one key for life, nobody rotates, and a single compromise is
    unbounded in time. After a rotation the new key signs what follows — and
    still cannot touch what preceded it."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    new = KeyPair.generate()
    try:
        entry = engine.rotate_signer(new.did())
        assert entry["outcome"] == new.did()
        engine.enforcer = new
        after = engine.verify_chain()
        assert after.ok, after.summary()
        assert after.rotations == 1

        # The holder of the new key edits an entry from before the rotation
        # and re-signs it with the only key they have.
        with engine.ledger.tx() as tx:
            rows = tx.chain_entries("default")
        target = rows[1]
        body = {k: target[k] for k in chainlib.ENTRY_FIELDS}
        body["outcome"] = "DENIED"
        resigned = chainlib.sign_entry(new, body)
        _sql(db, "UPDATE chain SET outcome=?, entry_hash=?, signature=?, signer=? "
                 "WHERE seq=?",
             "DENIED", resigned["entry_hash"], resigned["signature"], new.did(),
             target["seq"])
        broken = engine.verify_chain()
        assert not broken.ok
        assert broken.broken_at == target["seq"], broken
    finally:
        engine.ledger.close()


def test_g197_a_rotation_entry_is_not_a_claim_about_any_receipt(tmp_path):
    """It reuses `receipt_id`, so reconciliation would otherwise go looking for
    a receipt called `chain:signer-rotation` and report it missing."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    new = KeyPair.generate()
    try:
        engine.rotate_signer(new.did())
        engine.enforcer = new
        report = engine.verify_chain()
        assert report.ok, report.summary()
        assert not any(chainlib.ROTATION_ID in m for m in report.mismatches), report
        with pytest.raises(chainlib.ChainError):
            chainlib.rotation_body(seq=1, tenant="default", prev="x",
                                   new_signer="not-a-did", recorded_at="now")
    finally:
        engine.ledger.close()


def test_g198_the_reserved_rotation_id_is_not_a_hiding_place(tmp_path):
    """Rotation gave the chain an entry that reconciliation deliberately skips.
    That skip is a hole if a *receipt row* can wear the same name.

    The row here is a copy of a genuine receipt with only its id **column**
    renamed, so the body — and therefore its proof — still verifies. Before
    the fix it was invisible twice over: `unchained_receipts` found the
    rotation entry and called the row chained, and `reconcile` skipped the
    rotation entry so nothing ever compared it. I introduced this with the
    feature and found it by asking what the reserved name could be turned
    into.
    """
    engine, db, ids, _ = _world(tmp_path, calls=3)
    new = KeyPair.generate()
    try:
        engine.rotate_signer(new.did())
        engine.enforcer = new
        assert engine.verify_chain().ok, "a rotated chain must start clean"

        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        row = dict(con.execute("SELECT * FROM receipts LIMIT 1").fetchone())
        con.close()
        row["id"] = chainlib.ROTATION_ID
        row["nonce"] = "nonce-smuggled"
        _sql(db,
             f"INSERT INTO receipts ({','.join(row)}) "
             f"VALUES ({','.join('?' * len(row))})", *row.values())

        report = engine.verify_chain()
        assert not report.ok
        assert any("reserved id" in m for m in report.mismatches), report.mismatches
        # And from the other side: the count must stop crediting a rotation
        # entry as cover for a receipt.
        assert any("never recorded" in m for m in report.mismatches), report.mismatches
    finally:
        engine.ledger.close()


def test_g199_a_hostile_anchor_file_cannot_silence_the_verifier(tmp_path):
    """The anchor file is the one input a verifier reads from outside itself.

    It must fail closed: garbage in it may add noise, and may never remove a
    finding or end the run. The same class — one bad input emptying the whole
    report — has bitten this code three times.
    """
    from mandate.cli import _read_anchors

    engine, db, ids, _ = _world(tmp_path, calls=3)
    engine.ledger.close()
    _sql(db, "UPDATE receipts SET state='DENIED' WHERE id=?", ids[1])

    path = tmp_path / "hostile.jsonl"
    path.write_text("\n".join([
        '{"tenant": "default", "seq": "twelve", "entry_hash": "x"}',
        '{"tenant": null, "seq": 1, "entry_hash": null}',
        '{"tenant": "default", "seq": 99999999, "entry_hash": "sha256:0"}',
        '{"tenant": "default"}',
        "not json at all",
        "[1,2,3]",
        '{"tenant": "default", "seq": 1e400, "entry_hash": "x"}',
        "",
        '{"tenant": "default", "seq": -1, "entry_hash": "x"}',
        # Unhashable seqs. The first version of this gate used only scalars —
        # every one of them hashable — so it proved the verifier survives
        # *polite* garbage. A list reached `by_seq.get(seq)` and raised
        # TypeError out of verify_chain, emptying the report. Review found
        # what my own negative control had been too gentle to.
        '{"tenant": "default", "seq": [1, 2], "entry_hash": "x"}',
        '{"tenant": "default", "seq": {"a": 1}, "entry_hash": "x"}',
        '{"tenant": "default", "seq": true, "entry_hash": "x"}',
    ]) + "\n\n\n", encoding="utf-8")

    anchors = _read_anchors(str(path))
    engine = Engine(ledger=Ledger(db))
    try:
        report = engine.verify_chain(anchors=anchors)
        assert not report.ok
        # The point of the gate: the real tampering survives the noise.
        assert any("is stored as DENIED" in m for m in report.mismatches), report.mismatches
        # Six: the three unhashable ones plus 'twelve', a missing seq and
        # 1e400. Before the type check those four were reported as "the chain
        # no longer reaches it", which claims a real anchor diverged — a
        # verifier inventing a finding is its own kind of lie. Only -1 and
        # 99999999 are integers, so only those two are compared for real.
        assert sum("unusable seq" in m for m in report.mismatches) == 6, report.mismatches
        assert sum("no longer reaches it" in m for m in report.mismatches) == 2, report.mismatches
    finally:
        engine.ledger.close()


def test_g200_a_rotation_that_rotates_nothing_is_refused(tmp_path):
    """An operator who believes they rotated and did not is worse off than one
    who gets an error: they now trust a key that never changed."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    try:
        with pytest.raises(MandateError, match="changes nothing"):
            engine.rotate_signer(engine.enforcer.did())
        assert engine.verify_chain().ok, "the refusal must not have written anything"

        # And again once a rotation has happened, because then the head *is*
        # the rotation entry: its `signer` is the key that left and its
        # `outcome` is the key in charge. The first version of this guard
        # compared against `signer`, so it let a redundant B->B rotation
        # through — half-right, which is the worst kind of right.
        second = KeyPair.generate()
        engine.rotate_signer(second.did())
        engine.enforcer = second
        with pytest.raises(MandateError, match="changes nothing"):
            engine.rotate_signer(second.did())
        report = engine.verify_chain()
        assert report.ok, report.summary()
        assert report.rotations == 1, "the refused rotation must not have been written"
    finally:
        engine.ledger.close()


def test_g201_expect_signer_explains_itself_on_a_rotated_chain(tmp_path):
    """A rotated chain has more than one signer. An operator who knows only the
    current key and passes it gets BROKEN for a healthy chain — the cries-wolf
    failure this project has already shipped once."""
    engine, db, ids, _ = _world(tmp_path, calls=2)
    first = engine.enforcer.did()
    new = KeyPair.generate()
    try:
        engine.rotate_signer(new.did())
        engine.enforcer = new

        assert engine.verify_chain().ok
        assert engine.verify_chain(expect_signer=first).ok, (
            "--expect-signer names the key the chain starts with"
        )
        wrong = engine.verify_chain(expect_signer=new.did())
        assert not wrong.ok
        assert "takes over at seq" in (wrong.reason or ""), wrong.reason
        assert "starts with" in (wrong.reason or ""), wrong.reason
    finally:
        engine.ledger.close()
