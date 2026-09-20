"""Core enforcement engine. Library and gateway share this path."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import disclosure as disc
from .crypto import KeyPair, iso, sign_object, utcnow, verify_object
from .keys import EphemeralKeyProvider, KeyProvider, PersistedDevKeyProvider
from .ledger import Ledger, StorageError
from .models import AgentCard, Constraint, Grant, Intent, Principal, Receipt, new_id
from .policy import evaluate
from .routes import RouteRegistry
from .states import InvalidTransition
from .validate import (
    ValidationError,
    check_freshness,
    reject_forbidden,
    require_action,
    require_amount,
    require_audience,
    require_currency,
    require_did,
    require_nonce,
)


class MandateError(Exception):
    pass


def _day() -> str:
    return utcnow().strftime("%Y-%m-%d")


def _grant_from_doc(doc: dict[str, Any]) -> Grant:
    body = {k: v for k, v in doc.items() if k != "proof"}
    return Grant(
        id=body["id"],
        principal_did=body["principal_did"],
        agent_did=body["agent_did"],
        organization=body["organization"],
        purpose=body["purpose"],
        scopes=body["scopes"],
        not_before=body["not_before"],
        not_after=body["not_after"],
        constraints=body.get("constraints") or {},
        status=body.get("status", "active"),
        issued_at=body.get("issued_at", body["not_before"]),
    )


def _intent_from_signed(doc: dict[str, Any]) -> Intent:
    body = {k: v for k, v in doc.items() if k != "proof"}
    return Intent(
        id=body["id"],
        agent_did=body["agent_did"],
        grant_id=body["grant_id"],
        action=body["action"],
        amount=body.get("amount"),
        currency=body.get("currency") or "EUR",
        counterparty=body.get("counterparty"),
        summary=body.get("summary") or "",
        audience=body.get("audience") or "mandate://local",
        nonce=body.get("nonce") or "",
        context=body.get("context") or {},
        created_at=body.get("created_at") or iso(utcnow()),
    )


class Engine:
    def __init__(
        self,
        store=None,
        enforcer: KeyPair | None = None,
        key_provider: KeyProvider | None = None,
        ledger: Ledger | None = None,
        routes: RouteRegistry | None = None,
        executor=None,
        clock=None,
    ) -> None:
        if ledger is not None:
            self.ledger = ledger
        elif store is not None and hasattr(store, "root"):
            root = Path(store.root)
            self.ledger = Ledger(root / "mandate.sqlite")
            if key_provider is None:
                key_provider = PersistedDevKeyProvider(root / "enforcer-keys")
        else:
            self.ledger = Ledger(Path.cwd() / ".mandate" / "mandate.sqlite")

        if key_provider is not None:
            self.keys = key_provider
        elif enforcer is not None:
            from .keys import InMemoryKeyProvider

            self.keys = InMemoryKeyProvider(enforcer)
        else:
            self.keys = EphemeralKeyProvider()

        self.enforcer = self.keys.get_enforcer()
        self.enforcer_did = self.enforcer.did()
        self.routes = routes or RouteRegistry()
        self.executor = executor
        self._store = store
        self.clock = clock or utcnow

    def _now(self):
        return self.clock()

    def _day(self) -> str:
        return self._now().strftime("%Y-%m-%d")

    def register_principal(self, name: str, kind: str = "person", jurisdiction: str = "DE"):
        kp = KeyPair.generate()
        p = Principal(did=kp.did(), kind=kind, name=name, jurisdiction=jurisdiction)
        with self.ledger.tx() as tx:
            tx.put_principal(p.did, p.to_dict())
        if self._store is not None:
            try:
                self._store.put_principal(p)
            except TypeError:
                pass
        return p, kp

    def register_agent(self, name, operator_did, developer, model, skills=None):
        kp = KeyPair.generate()
        card = AgentCard(
            did=kp.did(),
            name=name,
            operator_did=operator_did,
            developer=developer,
            model=model,
            skills=skills or [],
        )
        signed = sign_object(kp, card.to_dict())
        with self.ledger.tx() as tx:
            tx.put_agent(card.did, signed)
        return card, kp

    def issue_grant(
        self,
        principal,
        principal_kp,
        agent,
        organization,
        purpose,
        scopes,
        not_after,
        constraints=None,
        not_before=None,
    ):
        grant = Grant.create(
            principal.did,
            agent.did,
            organization,
            purpose,
            scopes,
            not_after,
            constraints,
            not_before,
        )
        signed = sign_object(principal_kp, grant.to_dict())
        if not verify_object(signed, expected_did=principal.did):
            raise MandateError("grant signature failed")
        with self.ledger.tx() as tx:
            tx.put_grant(grant.id, principal.did, agent.did, "active", signed)
        return signed

    def revoke_grant(self, grant_id, principal_kp):
        with self.ledger.tx() as tx:
            g = tx.get_grant(grant_id)
            if not g:
                raise MandateError("unknown grant")
            if g["principal_did"] != principal_kp.did():
                raise MandateError("only the issuing principal can revoke")
            g = {k: v for k, v in g.items() if k != "proof"}
            g["status"] = "revoked"
            signed = sign_object(principal_kp, g)
            tx.put_grant(grant_id, signed["principal_did"], signed["agent_did"], "revoked", signed)
            tx.audit("grant.revoked", {"grant_id": grant_id})
        return signed

    def propose(self, agent_kp, grant_id, action, **kwargs):
        kwargs.setdefault("audience", "mandate://local")
        kwargs.setdefault("nonce", uuid4().hex)
        intent = Intent.create(agent_did=agent_kp.did(), grant_id=grant_id, action=action, **kwargs)
        signed = sign_object(agent_kp, intent.to_dict())
        return self.submit_intent(signed)

    def submit_intent(self, signed_intent: dict[str, Any]) -> dict[str, Any]:
        try:
            reject_forbidden(signed_intent)
            body = {k: v for k, v in signed_intent.items() if k != "proof"}
            require_did(body["agent_did"])
            require_action(body["action"])
            require_audience(body.get("audience") or "mandate://local")
            require_nonce(body.get("nonce") or "")
            require_currency(body.get("currency") or "EUR")
            require_amount(body.get("amount"))
            check_freshness(body.get("created_at") or iso(utcnow()))
        except (ValidationError, KeyError) as exc:
            raise MandateError(f"invalid intent: {exc}") from exc

        if not verify_object(signed_intent, expected_did=signed_intent["agent_did"]):
            raise MandateError("intent signature invalid")

        intent = _intent_from_signed(signed_intent)
        receipt_id = new_id("rcpt")

        try:
            with self.ledger.tx() as tx:
                tx.audit("intent.received", {"intent_id": intent.id, "grant_id": intent.grant_id}, intent.id)
                grant_doc = tx.get_grant(intent.grant_id)
                if not grant_doc:
                    raise MandateError("unknown grant")
                if not verify_object(grant_doc, expected_did=grant_doc["principal_did"]):
                    tx.audit("intent.denied", {"reason": "grant signature invalid"}, intent.id)
                    raise MandateError("grant signature invalid")
                grant = _grant_from_doc(grant_doc)

                if not tx.consume_nonce(intent.audience, intent.nonce, receipt_id):
                    tx.audit("replay.rejected", {"nonce": intent.nonce, "audience": intent.audience}, intent.id)
                    raise MandateError("replay: nonce already used for this audience")

                agent_doc = tx.get_agent(intent.agent_did)
                if not agent_doc:
                    raise MandateError("unknown agent")

                spent = tx.spent(grant.id, intent.currency, self._day())
                decision = evaluate(grant, intent, spent_today=spent)
                budget_day = None

                if decision.requires_human:
                    state = "HUMAN_REQUIRED"
                    tx.audit("intent.human_required", {"receipt_id": receipt_id}, intent.id)
                elif decision.allowed:
                    cap = (grant.constraints or {}).get("max_daily_amount")
                    cap_f = float(cap) if cap is not None else None
                    amt = intent.amount or 0.0
                    budget_day = self._day()
                    if not tx.reserve(grant.id, intent.currency, budget_day, amt, cap_f):
                        decision.allowed = False
                        decision.reasons = ["budget reservation failed"]
                        state = "DENIED"
                        budget_day = None
                        tx.audit("intent.denied", {"reason": "budget"}, intent.id)
                    else:
                        state = "AUTHORIZED"
                        tx.put_budget_binding(receipt_id, grant.id, intent.currency, budget_day, amt)
                        tx.audit("authorization.created", {"receipt_id": receipt_id}, intent.id)
                        tx.audit("budget.reserved", {"amount": amt, "day": budget_day}, intent.id)
                else:
                    state = "DENIED"
                    tx.audit("intent.denied", {"reasons": decision.reasons}, intent.id)

                agent = AgentCard(
                    did=agent_doc["did"],
                    name=agent_doc["name"],
                    operator_did=agent_doc["operator_did"],
                    developer=agent_doc["developer"],
                    model=agent_doc["model"],
                    skills=agent_doc.get("skills") or [],
                )
                disclosure = disc.article50(agent, grant, intent)
                rec = Receipt.create(
                    intent=signed_intent,
                    decision=decision.to_dict(),
                    grant_id=grant.id,
                    agent_did=agent.did,
                    principal_did=grant.principal_did,
                    disclosure=disclosure,
                    outcome=state,
                )
                rec.id = receipt_id
                signed_body = rec.to_dict()
                if budget_day:
                    signed_body["budget_day"] = budget_day
                signed_receipt = sign_object(self.enforcer, signed_body)
                tx.insert_receipt(
                    {
                        "id": receipt_id,
                        "grant_id": grant.id,
                        "agent_did": agent.did,
                        "principal_did": grant.principal_did,
                        "audience": intent.audience,
                        "nonce": intent.nonce,
                        "action": intent.action,
                        "amount": intent.amount,
                        "currency": intent.currency,
                        "state": state,
                        "execution_id": None,
                        "body": signed_receipt,
                        "budget_day": budget_day,
                    }
                )
                return signed_receipt
        except StorageError as exc:
            raise MandateError("storage error") from exc
        except InvalidTransition as exc:
            raise MandateError(str(exc)) from exc
        except MandateError:
            raise
        except Exception as exc:
            raise MandateError("policy or internal error") from exc

    def get_receipt(self, receipt_id: str) -> dict | None:
        with self.ledger.tx() as tx:
            row = tx.get_receipt(receipt_id)
        if not row:
            return None
        body = json.loads(row["body"])
        if not verify_object(body, expected_did=self.enforcer_did):
            raise MandateError("receipt was not signed by this enforcer")
        return body

    def approve(self, receipt_id: str, principal_kp: KeyPair, approval: dict | None = None) -> dict[str, Any]:
        """Revalidate then HUMAN_REQUIRED -> AUTHORIZED. Never jumps to EXECUTED."""
        if approval is None:
            row_preview = None
            with self.ledger.tx() as tx:
                row_preview = tx.get_receipt(receipt_id)
            if not row_preview:
                raise MandateError("unknown receipt")
            body = json.loads(row_preview["body"])
            intent = body["intent"]
            approval = sign_object(
                principal_kp,
                {
                    "type": "MandateApproval",
                    "approval_id": new_id("appr"),
                    "receipt_id": receipt_id,
                    "intent_id": intent["id"],
                    "grant_id": body["grant_id"],
                    "principal_did": body["principal_did"],
                    "agent_did": body["agent_did"],
                    "audience": intent.get("audience"),
                    "action": intent.get("action"),
                    "amount": intent.get("amount"),
                    "currency": intent.get("currency"),
                    "nonce": uuid4().hex,
                    "intent_nonce": intent.get("nonce"),
                    "created_at": iso(utcnow()),
                    "not_after": iso(utcnow() + timedelta(minutes=10)),
                },
            )
        return self.submit_approval(approval, principal_kp.did())

    def submit_approval(self, signed_approval: dict[str, Any], expected_principal: str | None = None) -> dict[str, Any]:
        try:
            reject_forbidden(signed_approval)
        except ValidationError as exc:
            raise MandateError(str(exc)) from exc
        if not verify_object(signed_approval):
            raise MandateError("approval signature invalid")
        a = {k: v for k, v in signed_approval.items() if k != "proof"}
        signer = signed_approval["proof"]["verificationMethod"].split("#")[0]
        if expected_principal and signer != expected_principal:
            raise MandateError("approval signer mismatch")
        if a.get("principal_did") and a["principal_did"] != signer:
            raise MandateError("approval principal mismatch")

        try:
            check_freshness(a.get("created_at") or iso(utcnow()), max_age_s=600)
        except ValidationError as exc:
            raise MandateError(str(exc)) from exc
        if a.get("not_after"):
            from datetime import datetime, timezone

            exp = datetime.strptime(a["not_after"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if utcnow() > exp:
                raise MandateError("approval expired")

        try:
            with self.ledger.tx() as tx:
                tx.audit("approval.received", {"receipt_id": a.get("receipt_id")}, a.get("approval_id"))
                row = tx.get_receipt(a["receipt_id"])
                if not row:
                    raise MandateError("unknown receipt")
                if row["state"] != "HUMAN_REQUIRED":
                    tx.audit("approval.rejected", {"reason": f"state {row['state']}"}, a.get("approval_id"))
                    raise MandateError("receipt is not waiting for human approval")
                body = json.loads(row["body"])
                if not verify_object(body, expected_did=self.enforcer_did):
                    raise MandateError("receipt was not signed by this enforcer")
                if signer != body["principal_did"]:
                    tx.audit("approval.rejected", {"reason": "wrong principal"}, a.get("approval_id"))
                    raise MandateError("only the grant principal can approve")

                intent_doc = body["intent"]
                for field in ("intent_id", "grant_id", "agent_did", "audience", "action", "amount", "currency"):
                    if field == "intent_id":
                        if a.get("intent_id") != intent_doc["id"]:
                            raise MandateError("approval does not bind this intent")
                        continue
                    if a.get(field) is not None and a.get(field) != intent_doc.get(field) and a.get(field) != body.get(field):
                        raise MandateError(f"approval field mismatch: {field}")

                approval_id = a.get("approval_id") or new_id("appr")
                approval_nonce = a.get("nonce") or uuid4().hex
                if not tx.put_approval(approval_id, a["receipt_id"], approval_nonce, signed_approval):
                    tx.audit("replay.rejected", {"kind": "approval"}, approval_id)
                    raise MandateError("approval replay")
                tx.consume_approval(approval_id)

                grant_doc = tx.get_grant(body["grant_id"])
                if not grant_doc or not verify_object(grant_doc, expected_did=grant_doc["principal_did"]):
                    raise MandateError("grant signature invalid")
                grant = _grant_from_doc(grant_doc)
                intent = _intent_from_signed(intent_doc)
                spent = tx.spent(grant.id, intent.currency, self._day())
                decision = evaluate(grant, intent, spent_today=spent, skip_human=True)
                if not decision.allowed:
                    new_body = {k: v for k, v in body.items() if k != "proof"}
                    new_body["decision"] = decision.to_dict()
                    new_body["outcome"] = "DENIED"
                    new_body["approval"] = signed_approval
                    signed = sign_object(self.enforcer, new_body)
                    if not tx.cas_state(a["receipt_id"], "HUMAN_REQUIRED", "DENIED", signed):
                        raise MandateError("invalid state transition")
                    tx.audit("approval.rejected", {"reason": decision.reasons}, a.get("approval_id"))
                    return signed

                cap = (grant.constraints or {}).get("max_daily_amount")
                cap_f = float(cap) if cap is not None else None
                amt = intent.amount or 0.0
                budget_day = self._day()
                if not tx.reserve(grant.id, intent.currency, budget_day, amt, cap_f):
                    new_body = {k: v for k, v in body.items() if k != "proof"}
                    new_body["decision"] = {"allowed": False, "reasons": ["budget reservation failed"], "requires_human": False}
                    new_body["outcome"] = "DENIED"
                    signed = sign_object(self.enforcer, new_body)
                    tx.cas_state(a["receipt_id"], "HUMAN_REQUIRED", "DENIED", signed)
                    return signed

                new_body = {k: v for k, v in body.items() if k != "proof"}
                new_body["decision"] = {
                    "allowed": True,
                    "requires_human": False,
                    "reasons": ["human approved and revalidated"],
                    "approval_id": a.get("approval_id"),
                }
                new_body["outcome"] = "AUTHORIZED"
                new_body["budget_day"] = budget_day
                signed = sign_object(self.enforcer, new_body)
                if not tx.cas_state(a["receipt_id"], "HUMAN_REQUIRED", "AUTHORIZED", signed):
                    raise MandateError("invalid state transition")
                tx.put_budget_binding(a["receipt_id"], grant.id, intent.currency, budget_day, amt)
                tx.set_receipt_budget_day(a["receipt_id"], budget_day)
                tx.audit("authorization.created", {"receipt_id": a["receipt_id"], "via": "approval", "day": budget_day}, a.get("approval_id"))
                return signed
        except StorageError as exc:
            raise MandateError("storage error") from exc

    def execute(self, receipt_id: str, idempotency_key: str | None = None) -> dict[str, Any]:
        if self.executor is None:
            raise MandateError("no executor configured")
        executor = self.executor

        try:
            with self.ledger.tx() as tx:
                existing = tx.get_execution_by_receipt(receipt_id)
                if existing:
                    row = tx.get_receipt(receipt_id)
                    return json.loads(row["body"])
                row = tx.get_receipt(receipt_id)
                if not row:
                    raise MandateError("unknown receipt")
                if row["state"] != "AUTHORIZED":
                    raise MandateError(f"invalid state transition {row['state']} -> EXECUTING")
                body = json.loads(row["body"])
                if not verify_object(body, expected_did=self.enforcer_did):
                    raise MandateError("receipt was not signed by this enforcer")
                # Revalidate in the same transaction as the execution claim.
                # A revocation committed before this claim must prevent dispatch.
                intent = _intent_from_signed(body["intent"])
                if not verify_object(body["intent"], expected_did=body["agent_did"]):
                    raise MandateError("intent signature invalid")
                for field in ("grant_id", "agent_did", "audience", "action", "amount", "currency", "nonce"):
                    if row[field] != getattr(intent, field):
                        raise MandateError("receipt execution fields mismatch")
                grant_doc = tx.get_grant(body["grant_id"])
                if not grant_doc or not verify_object(grant_doc, expected_did=body["principal_did"]):
                    raise MandateError("grant signature invalid")
                grant = _grant_from_doc(grant_doc)
                if grant.id != intent.grant_id or grant.principal_did != body["principal_did"]:
                    raise MandateError("grant identity mismatch")
                binding = tx.get_budget_binding(receipt_id)
                if not binding:
                    raise MandateError("authorization lacks budget binding")
                if (binding["grant_id"], binding["currency"], binding["amount"]) != (
                    intent.grant_id, intent.currency, intent.amount or 0,
                ):
                    raise MandateError("budget binding mismatch")
                # The current reservation already counts toward this day's cap.
                spent = max(0, tx.spent(grant.id, intent.currency, binding["day"]) - binding["amount"])
                approval = tx.get_approval_by_receipt(receipt_id)
                human_approved = False
                if approval and approval["consumed"]:
                    approval_body = json.loads(approval["body"])
                    human_approved = (
                        verify_object(approval_body, expected_did=body["principal_did"])
                        and approval_body.get("receipt_id") == receipt_id
                        and approval_body.get("intent_id") == intent.id
                    )
                decision = evaluate(grant, intent, spent_today=spent, skip_human=human_approved)
                if not decision.allowed:
                    denied = {k: v for k, v in body.items() if k != "proof"}
                    denied.update(outcome="DENIED", decision=decision.to_dict())
                    signed = sign_object(self.enforcer, denied)
                    if not tx.cas_state(receipt_id, "AUTHORIZED", "DENIED", signed):
                        raise MandateError("authorization already consumed")
                    tx.release_budget(grant.id, intent.currency, binding["day"], binding["amount"])
                    tx.audit("execution.denied", {"receipt_id": receipt_id, "reasons": decision.reasons}, receipt_id)
                    return signed
                audience = row["audience"]
                route = self.routes.get(audience)
                if route is None:
                    raise MandateError("unknown route")
                execution_id = new_id("exec")
                idem = idempotency_key or execution_id
                prior = tx.get_execution_by_idem(idem)
                if prior:
                    r2 = tx.get_receipt(prior["receipt_id"])
                    return json.loads(r2["body"])
                if not tx.cas_state(receipt_id, "AUTHORIZED", "EXECUTING", body):
                    raise MandateError("authorization already consumed")
                tx.set_execution(receipt_id, execution_id)
                tx.put_execution(execution_id, receipt_id, idem, "EXECUTING", {"started": iso(utcnow())})
                tx.audit("execution.started", {"execution_id": execution_id, "receipt_id": receipt_id}, receipt_id)
        except StorageError as exc:
            raise MandateError("storage error") from exc

        payload = {
            "action": row["action"],
            "amount": row["amount"],
            "currency": row["currency"],
            "execution_id": execution_id,
        }
        result = executor.forward(route, route.allowed_methods[0], route.allowed_paths[0], payload, idem)

        try:
            with self.ledger.tx() as tx:
                row = tx.get_receipt(receipt_id)
                body = json.loads(row["body"])
                new_body = {k: v for k, v in body.items() if k != "proof"}
                new_body["outcome"] = result.state
                new_body["execution"] = {
                    "execution_id": execution_id,
                    "state": result.state,
                    "http_status": result.status,
                    "latency_ms": result.latency_ms,
                    "response_hash": result.body_hash,
                    "idempotency_key": idem,
                    "enforcer_did": self.enforcer_did,
                    "predecessor_id": receipt_id,
                    "error": result.error,
                }
                signed = sign_object(self.enforcer, new_body)
                dst = result.state
                if not tx.cas_state(receipt_id, "EXECUTING", dst, signed):
                    raise MandateError("invalid state transition")
                amt = float(row["amount"] or 0)
                binding = tx.get_budget_binding(receipt_id)
                if binding:
                    gid, curr, day, bamt = binding["grant_id"], binding["currency"], binding["day"], float(binding["amount"])
                else:
                    gid, curr, day, bamt = row["grant_id"], row["currency"] or "EUR", self._day(), amt
                if result.state == "EXECUTED":
                    tx.commit_budget(gid, curr, day, bamt)
                    tx.audit("execution.succeeded", {"execution_id": execution_id, "budget_day": day}, receipt_id)
                elif result.state == "EXECUTION_FAILED":
                    tx.release_budget(gid, curr, day, bamt)
                    tx.audit("execution.failed", {"execution_id": execution_id, "budget_day": day}, receipt_id)
                else:
                    tx.audit("execution.unknown", {"execution_id": execution_id, "budget_day": day}, receipt_id)
                tx.put_execution(execution_id, receipt_id, idem, result.state, new_body["execution"])
                return signed
        except StorageError as exc:
            raise MandateError("storage error") from exc
