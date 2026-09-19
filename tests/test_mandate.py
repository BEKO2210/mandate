from datetime import timedelta

from mandate.crypto import KeyPair, public_bytes_to_did, sign_object, utcnow, verify, verify_object
from mandate.engine import Engine
from mandate.models import Constraint, Grant, Intent
from mandate.policy import evaluate
from mandate.store import Store


def test_did_roundtrip():
    kp = KeyPair.generate()
    did = kp.did()
    assert did.startswith("did:key:z")
    assert public_bytes_to_did(kp.public_bytes()) == did
    sig = kp.sign_hex(b"mandate")
    assert verify(did, b"mandate", sig)
    assert not verify(did, b"other", sig)


def test_sign_object():
    kp = KeyPair.generate()
    obj = sign_object(kp, {"hello": "world", "n": 1})
    assert verify_object(obj, kp.did())
    obj["hello"] = "tampered"
    assert not verify_object(obj, kp.did())


def test_full_flow(tmp_path):
    engine = Engine(Store(tmp_path))
    person, pkp = engine.register_principal("Belkis")
    org, _ = engine.register_principal("Aslani GmbH", kind="org")
    agent, akp = engine.register_agent("ProcureBot", org.did, "Mandate", "demo", ["buy"])
    grant = engine.issue_grant(
        person, pkp, agent, organization="Aslani GmbH", purpose="buy office supplies",
        scopes=["purchase.office"], not_after=utcnow() + timedelta(days=5),
        constraints=Constraint(max_amount=5000, require_human_above=2500, counterparties_deny=["bad.example"]),
    )
    assert verify_object(grant, person.did)
    ok = engine.propose(akp, grant["id"], action="purchase.office", amount=120, summary="paper")
    assert ok["decision"]["allowed"] is True
    human = engine.propose(akp, grant["id"], action="purchase.office", amount=3000, summary="desk")
    assert human["decision"]["allowed"] is False and human["decision"]["requires_human"] is True
    deny = engine.propose(akp, grant["id"], action="purchase.office", amount=9000, summary="server")
    assert deny["decision"]["allowed"] is False
    scope = engine.propose(akp, grant["id"], action="wire.payroll", amount=10, summary="salary")
    assert scope["decision"]["allowed"] is False
    blocked = engine.propose(akp, grant["id"], action="purchase.office", amount=10, counterparty="bad.example", summary="toner")
    assert blocked["decision"]["allowed"] is False


def test_evaluate_expiry():
    g = Grant.create("did:key:zP", "did:key:zA", "Org", "x", ["purchase.office"], not_after=utcnow() - timedelta(days=1))
    i = Intent.create("did:key:zA", g.id, "purchase.office", amount=1)
    d = evaluate(g, i)
    assert d.allowed is False
    assert any("expired" in r for r in d.reasons)
