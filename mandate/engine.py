from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from . import disclosure as disc
from .crypto import KeyPair, sign_object, verify_object
from .models import AgentCard, Constraint, Grant, Intent, Principal, Receipt
from .policy import evaluate
from .store import Store


class MandateError(Exception):
    pass


class Engine:
    def __init__(self, store: Store | None = None, enforcer: KeyPair | None = None) -> None:
        self.store = store or Store()
        self.enforcer = enforcer or KeyPair.generate()
        self.enforcer_did = self.enforcer.did()

    def register_principal(self, name: str, kind: str = "person", jurisdiction: str = "DE"):
        kp = KeyPair.generate()
        p = Principal(did=kp.did(), kind=kind, name=name, jurisdiction=jurisdiction)
        self.store.put_principal(p)
        return p, kp

    def register_agent(self, name, operator_did, developer, model, skills=None):
        kp = KeyPair.generate()
        card = AgentCard(did=kp.did(), name=name, operator_did=operator_did, developer=developer, model=model, skills=skills or [])
        signed = sign_object(kp, card.to_dict())
        self.store.put_agent(card, signed)
        return card, kp

    def issue_grant(self, principal, principal_kp, agent, organization, purpose, scopes, not_after, constraints=None, not_before=None):
        grant = Grant.create(principal.did, agent.did, organization, purpose, scopes, not_after, constraints, not_before)
        signed = sign_object(principal_kp, grant.to_dict())
        if not verify_object(signed, expected_did=principal.did):
            raise MandateError("grant signature failed")
        self.store.put_grant(signed)
        return signed

    def revoke_grant(self, grant_id, principal_kp):
        g = self.store.get_grant(grant_id)
        if not g:
            raise MandateError("unknown grant")
        if g["principal_did"] != principal_kp.did():
            raise MandateError("only the issuing principal can revoke")
        g = dict(g)
        g["status"] = "revoked"
        signed = sign_object(principal_kp, {k: v for k, v in g.items() if k != "proof"})
        self.store.put_grant(signed)
        return signed

    def propose(self, agent_kp, grant_id, action, **kwargs):
        grant_doc = self.store.get_grant(grant_id)
        if not grant_doc:
            raise MandateError("unknown grant")
        if not verify_object(grant_doc, expected_did=grant_doc["principal_did"]):
            raise MandateError("grant signature invalid")
        grant = _grant_from_doc(grant_doc)
        kwargs.setdefault("audience", "mandate://local")
        kwargs.setdefault("nonce", uuid4().hex)
        intent = Intent.create(agent_did=agent_kp.did(), grant_id=grant_id, action=action, **kwargs)
        signed_intent = sign_object(agent_kp, intent.to_dict())
        if not self.store.consume_nonce(intent.nonce, intent.audience):
            raise MandateError("replay: nonce already used for this audience")
        spent = self.store.spent_today(grant_id, intent.currency)
        decision = evaluate(grant, intent, spent_today=spent)
        agent = self.store.get_agent(agent_kp.did())
        if not agent:
            raise MandateError("unknown agent")
        disclosure = disc.article50(agent, grant, intent)
        outcome = "proposed" if decision.allowed else "blocked"
        receipt = Receipt.create(
            intent=signed_intent, decision=decision.to_dict(), grant_id=grant.id,
            agent_did=agent.did, principal_did=grant.principal_did,
            disclosure=disclosure, outcome=outcome,
        )
        signed_receipt = sign_object(self.enforcer, receipt.to_dict())
        self.store.put_receipt(signed_receipt)
        if decision.allowed and intent.amount:
            self.store.add_spend(grant_id, intent.currency, intent.amount)
        return signed_receipt

    def approve(self, receipt_id, principal_kp):
        receipt = self.store.get_receipt(receipt_id)
        if not receipt:
            raise MandateError("unknown receipt")
        if receipt["principal_did"] != principal_kp.did():
            raise MandateError("only the grant principal can approve")
        if not receipt["decision"].get("requires_human"):
            raise MandateError("receipt is not waiting for human approval")
        if not verify_object(receipt, expected_did=self.enforcer_did):
            raise MandateError("receipt was not signed by this enforcer")
        approval = sign_object(principal_kp, {"type": "MandateApproval", "receipt_id": receipt_id, "grant_id": receipt["grant_id"], "intent_id": receipt["intent"]["id"]})
        body = {k: v for k, v in receipt.items() if k != "proof"}
        body["decision"] = {**body["decision"], "allowed": True, "requires_human": False, "reasons": ["human approved"], "approval": approval}
        body["outcome"] = "executed"
        amount = body["intent"].get("amount")
        currency = body["intent"].get("currency") or "EUR"
        if amount:
            self.store.add_spend(body["grant_id"], currency, float(amount))
        signed = sign_object(self.enforcer, body)
        self.store.put_receipt(signed)
        return signed


def _grant_from_doc(doc):
    body = {k: v for k, v in doc.items() if k != "proof"}
    return Grant(
        id=body["id"], principal_did=body["principal_did"], agent_did=body["agent_did"],
        organization=body["organization"], purpose=body["purpose"], scopes=body["scopes"],
        not_before=body["not_before"], not_after=body["not_after"],
        constraints=body.get("constraints") or {}, status=body.get("status", "active"),
        issued_at=body.get("issued_at", body["not_before"]),
    )
