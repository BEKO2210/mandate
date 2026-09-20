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
