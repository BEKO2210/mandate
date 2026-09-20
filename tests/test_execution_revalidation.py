"""Execution must revalidate that delegated authority is still current."""

from mandate.engine import MandateError


def test_revoked_after_authorization_never_reaches_upstream(harness):
    engine = harness["engine"]
    dummy = harness["dummy"]
    grant = harness["grant"]
    pkp = harness["pkp"]
    akp = harness["akp"]

    authorized = engine.propose(
        akp,
        grant["id"],
        action="purchase.office",
        amount=10,
        audience="mandate://procurement",
    )
    assert authorized["outcome"] == "AUTHORIZED"

    engine.revoke_grant(grant["id"], pkp)

    try:
        result = engine.execute(authorized["id"])
    except MandateError:
        result = None

    if result is not None:
        assert result["outcome"] != "EXECUTED"

    assert dummy.call_count() == 0


def _authorize(harness):
    return harness['engine'].propose(
        harness['akp'], harness['grant']['id'], action='purchase.office',
        amount=10, audience='mandate://procurement',
    )


def test_revocation_survives_restart_and_releases_reservation(harness):
    from mandate.engine import Engine
    from mandate.ledger import Ledger
    e = harness['engine']
    receipt = _authorize(harness)
    e.revoke_grant(harness['grant']['id'], harness['pkp'])
    path = e.ledger.path
    e.ledger.close()
    restarted = Engine(ledger=Ledger(path), key_provider=harness['keys'],
                       routes=e.routes, executor=e.executor)
    try:
        result = restarted.execute(receipt['id'])
        assert result['outcome'] == 'DENIED'
        with restarted.ledger.tx() as tx:
            assert tx.get_execution_by_receipt(receipt['id']) is None
            assert tx.budget_snapshot(harness['grant']['id'], 'EUR', receipt['budget_day'])['reserved'] == 0
        assert harness['dummy'].call_count() == 0
    finally:
        restarted.ledger.close()


def test_expiry_after_authorization_prevents_dispatch(harness, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from mandate.crypto import utcnow
    receipt = _authorize(harness)
    future = utcnow() + timedelta(days=6)
    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return future.astimezone(tz or timezone.utc)
    monkeypatch.setattr('mandate.policy.datetime', FutureDateTime)
    result = harness['engine'].execute(receipt['id'])
    assert result['outcome'] == 'DENIED'
    assert harness['dummy'].call_count() == 0


def test_execution_revalidation_does_not_double_count_reservation(harness):
    from datetime import timedelta
    from mandate.crypto import utcnow
    from mandate.models import Constraint
    e = harness['engine']
    grant = e.issue_grant(harness['person'], harness['pkp'], harness['agent'],
        'test', 'test', ['purchase.office'], utcnow() + timedelta(days=1),
        Constraint(max_daily_amount=10))
    receipt = e.propose(harness['akp'], grant['id'], 'purchase.office',
                       amount=10, audience='mandate://procurement')
    assert e.execute(receipt['id'])['outcome'] == 'EXECUTED'
    assert harness['dummy'].call_count() == 1


def test_unsigned_execution_column_change_prevents_dispatch(harness):
    import pytest
    receipt = _authorize(harness)
    e = harness['engine']
    with e.ledger.tx():
        e.ledger._conn.execute('UPDATE receipts SET amount=999 WHERE id=?', (receipt['id'],))
    with pytest.raises(MandateError, match='fields mismatch'):
        e.execute(receipt['id'])
    assert harness['dummy'].call_count() == 0
