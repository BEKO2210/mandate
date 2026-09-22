"""Core enforcement engine. Library and gateway share this path."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import chain as chainlib
from . import disclosure as disc
from .crypto import KeyPair, canonical_json, iso, sign_object, utcnow, verify_object
from .auth import DEFAULT_TENANT
from .executor import ExecutionResult
from .keys import EphemeralKeyProvider, KeyProvider, PersistedDevKeyProvider
from .ledger import Ledger, StorageError
from .models import AgentCard, Grant, Intent, Principal, Receipt, new_id
from .money import MoneyError
from .payload import PayloadError, body_hash, build_payload, encode
from .policy import constraint_minor, evaluate, intent_amount_minor
from .routes import RouteRegistry
from .signing import Signer, SigningError
from .states import InvalidTransition
from .validate import (
    ValidationError,
    check_freshness,
    reject_forbidden,
    require_action,
    require_amount,
    require_amount_agreement,
    require_audience,
    require_context,
    require_currency,
    require_did,
    require_nonce,
)

# A claimed execution older than this is no longer in flight in this process.
DEFAULT_EXECUTION_STALE_AFTER_S = 900

#: An executor's error text goes into a signed receipt. It used to go in
#: whole, so an upstream with a verbose error could push the receipt past
#: its signer's message cap *after* the call had been made: the real outcome
#: was lost and the receipt sat in EXECUTING until the next restart.
ERROR_LIMIT = 200

#: The smallest resolution the pre-dispatch size check keeps room for, so an
#: unknown outcome can always be resolved with at least this much plain ASCII.
_RESOLUTION_RESERVE = {"operator": 32, "reason": 128}


def bounded_error(text: Any) -> str | None:
    """Printable ASCII without characters JSON escapes, at most ERROR_LIMIT
    long: exactly one byte per character in the signed receipt, whatever the
    upstream said."""
    if text is None:
        return None
    clean = "".join(
        ("'" if ch in "\"\\" else ch) if " " <= ch <= "~" else "?" for ch in str(text)
    )
    return clean if len(clean) <= ERROR_LIMIT else clean[: ERROR_LIMIT - 3] + "..."


def _largest_outcome(claim: dict[str, Any]) -> dict[str, Any]:
    """A body at least as large as any the engine may sign for this claim
    after dispatch: the result, a reconciler's EXECUTION_UNKNOWN, and a
    resolution on top of either. Every variable field is at its maximum."""
    body = dict(claim)
    body["outcome"] = "EXECUTION_UNKNOWN"
    execution = dict(claim["execution"])
    execution.update(
        state="EXECUTION_UNKNOWN",
        http_status=999,
        latency_ms=10**9,
        response_hash="f" * 64,
        error="x" * ERROR_LIMIT,  # bounded_error makes every character one byte
        reconciled_at="0000-00-00T00:00:00Z",
        resolution={
            "from": "EXECUTION_UNKNOWN",
            "decided": "EXECUTION_FAILED",
            "by": "x" * _RESOLUTION_RESERVE["operator"],
            "reason": "x" * _RESOLUTION_RESERVE["reason"],
            "at": "0000-00-00T00:00:00Z",
            "budget_day": "0000-00-00",
        },
    )
    body["execution"] = execution
    return body


class MandateError(Exception):
    pass


class ExecutionUnknown(MandateError):
    """The call was dispatched and its outcome could not be recorded.

    Distinct from every other failure in `execute()` because the upstream may
    already have acted. The receipt stays EXECUTING with its reservation held,
    so `reconcile_stale_executions()` closes it out; the caller must be told
    "unknown", never "not dispatched".
    """

    def __init__(self, message: str, receipt_id: str | None = None) -> None:
        super().__init__(message)
        self.receipt_id = receipt_id


def _day() -> str:
    return utcnow().strftime("%Y-%m-%d")


def _scoped_idem(tenant: str, idem: str) -> str:
    """Tenant-scoped storage form of a caller-chosen idempotency key.

    Length-prefixed so no tenant name or key content can be crafted to collide
    with another tenant's pair.
    """
    return f"{len(tenant)}:{tenant}:{idem}"


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
        enforcer: Signer | None = None,
        key_provider: KeyProvider | None = None,
        ledger: Ledger | None = None,
        routes: RouteRegistry | None = None,
        executor=None,
        clock=None,
        execution_stale_after_s: int = DEFAULT_EXECUTION_STALE_AFTER_S,
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
        self.execution_stale_after_s = execution_stale_after_s

    def _now(self):
        return self.clock()

    def _chain(self, tx, tenant: str, receipt_id: str, outcome: str, body: dict) -> dict:
        """Build and sign the entry that records one receipt state.

        Called inside the caller's transaction so the head it reads is the head
        the entry is appended to. Every receipt write in this engine goes
        through here; the ledger refuses a write that does not.
        """
        head = tx.chain_head(tenant)
        entry = chainlib.entry_body(
            seq=(head["seq"] + 1) if head else 1,
            tenant=tenant,
            # Entry 1 points at a genesis that binds the legacy baseline, so
            # raising that baseline later breaks the chain at its first link.
            prev=(
                head["entry_hash"] if head
                else chainlib.genesis(tenant, tx.legacy_receipts(tenant))
            ),
            receipt_id=receipt_id,
            outcome=outcome,
            body_hash=chainlib.body_hash(body),
            recorded_at=iso(self._now()),
        )
        return chainlib.sign_entry(self.enforcer, entry)

    def chain_head(self, tenant: str = DEFAULT_TENANT) -> dict | None:
        """The current head, to keep somewhere this deployment does not own.

        A chain proves nothing about what was deleted from its end. Handing the
        head to anyone else — a log, another host, the caller who holds the
        receipt — is what turns truncation from invisible into provable.
        """
        with self.ledger.tx() as tx:
            return tx.chain_head(tenant)

    def anchor_chain(self, tenant: str = DEFAULT_TENANT) -> dict | None:
        """A head, stamped, in a form that can be written down elsewhere.

        `chain_head` hands out the same value; this exists so that keeping one
        is a thing the tool does rather than advice in a document. An anchor
        nobody stores is worth exactly as much as no anchor.
        """
        head = self.chain_head(tenant)
        if not head:
            return None
        return {
            "tenant": tenant,
            "seq": head["seq"],
            "entry_hash": head["entry_hash"],
            "anchored_at": iso(self._now()),
        }

    def rotate_signer(self, new_signer: str, tenant: str = DEFAULT_TENANT) -> dict:
        """Hand signing authority to another key, signed by the one leaving.

        Until now a chain was pinned to one key for life: rotating broke
        verification, so the practical advice was never to rotate, which makes
        a single compromise unbounded in time. The rotation entry is signed by
        the *outgoing* key, so whoever steals the current one still cannot
        rewrite anything that happened before they got it.
        """
        with self.ledger.tx() as tx:
            head = tx.chain_head(tenant)
            if not head:
                raise MandateError(
                    "a chain with no entries has no signer to rotate away from"
                )
            # After a rotation the head *is* the rotation entry, whose `signer`
            # is the key that left and whose `outcome` is the key now in
            # charge. Comparing against `signer` therefore compared against
            # the wrong key and let a second, redundant rotation through.
            # Review found it; the guard was half-right, which is the worst
            # kind of right.
            active = head["outcome"] if chainlib.is_rotation(head) else head["signer"]
            if new_signer == active:
                # An operator who believes they rotated and did not is worse
                # off than one who gets an error: they now trust a key that
                # never changed. Refusing the no-op is the safer answer.
                raise MandateError(
                    f"the chain is already signed by {new_signer}; rotating to "
                    f"the same key changes nothing and would hide that"
                )

            entry = chainlib.rotation_body(
                seq=head["seq"] + 1, tenant=tenant, prev=head["entry_hash"],
                new_signer=new_signer, recorded_at=iso(self._now()),
            )
            signed = chainlib.sign_entry(self.enforcer, entry)
            tx.append_chain(signed)
        return signed

    def verify_chain(
        self, tenant: str = DEFAULT_TENANT, expect_head: str | None = None,
        expect_signer: str | None = None, anchors: list[dict] | None = None,
    ) -> chainlib.ChainReport:
        """Walk the chain and compare it against the receipts it commits to.

        `expect_signer` is not defaulted to this engine's enforcer DID: an
        engine built only to audit a database has a key of its own, and
        assuming otherwise made every healthy chain report as broken.
        """
        with self.ledger.tx() as tx:
            entries = tx.chain_entries(tenant)
            stored = tx.receipt_digests(tenant)
            unchained = tx.unchained_receipts(tenant)
            legacy = tx.legacy_receipts(tenant)
        return chainlib.verify_chain(
            entries, tenant, signer_did=expect_signer, expect_head=expect_head,
            stored=stored, unchained_receipts=unchained, legacy_receipts=legacy,
            anchors=anchors,
        )

    def _day(self) -> str:
        return self._now().strftime("%Y-%m-%d")

    def register_principal(
        self, name: str, kind: str = "person", jurisdiction: str = "DE",
        tenant: str = DEFAULT_TENANT, signer: Signer | None = None,
    ):
        # With a signer the engine never sees a private key: the DID comes from
        # the key manager, and the caller gets the same signer back in place of
        # the keypair it would otherwise have had to store.
        kp = signer if signer is not None else KeyPair.generate()
        p = Principal(did=kp.did(), kind=kind, name=name, jurisdiction=jurisdiction)
        with self.ledger.tx() as tx:
            tx.put_principal(p.did, p.to_dict(), tenant=tenant)
        if self._store is not None:
            try:
                self._store.put_principal(p)
            except TypeError:
                pass
        return p, kp

    def register_agent(
        self, name, operator_did, developer, model, skills=None, tenant: str = DEFAULT_TENANT,
        signer: Signer | None = None,
    ):
        kp = signer if signer is not None else KeyPair.generate()
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
            tx.put_agent(card.did, signed, tenant=tenant)
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
        tenant: str = DEFAULT_TENANT,
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
            # Authority must not cross a tenant boundary at issue time either.
            if tx.get_agent(agent.did, tenant=tenant) is None:
                raise MandateError("unknown agent")
            tx.put_grant(grant.id, principal.did, agent.did, "active", signed, tenant=tenant)
        return signed

    def revoke_grant(self, grant_id, principal_kp, tenant: str = DEFAULT_TENANT):
        with self.ledger.tx() as tx:
            g = tx.get_grant(grant_id, tenant=tenant)
            if not g:
                raise MandateError("unknown grant")
            if g["principal_did"] != principal_kp.did():
                raise MandateError("only the issuing principal can revoke")
            g = {k: v for k, v in g.items() if k != "proof"}
            g["status"] = "revoked"
            signed = sign_object(principal_kp, g)
            tx.put_grant(
                grant_id, signed["principal_did"], signed["agent_did"], "revoked", signed,
                tenant=tenant,
            )
            tx.audit("grant.revoked", {"grant_id": grant_id})
        return signed

    def propose(self, agent_kp, grant_id, action, tenant: str = DEFAULT_TENANT, **kwargs):
        kwargs.setdefault("audience", "mandate://local")
        kwargs.setdefault("nonce", uuid4().hex)
        intent = Intent.create(agent_did=agent_kp.did(), grant_id=grant_id, action=action, **kwargs)
        signed = sign_object(agent_kp, intent.to_dict())
        return self.submit_intent(signed, tenant=tenant)

    def submit_intent(
        self, signed_intent: dict[str, Any], tenant: str = DEFAULT_TENANT
    ) -> dict[str, Any]:
        try:
            reject_forbidden(signed_intent)
            body = {k: v for k, v in signed_intent.items() if k != "proof"}
            require_did(body["agent_did"])
            require_action(body["action"])
            require_audience(body.get("audience") or "mandate://local")
            require_nonce(body.get("nonce") or "")
            currency = require_currency(body.get("currency") or "EUR")
            amount_minor = require_amount(body.get("amount"), currency)
            require_amount_agreement(body, amount_minor)
            require_context(body.get("context"))
            # Required, not defaulted to now: an intent without a creation
            # time was fresh forever, and only a nonce remembered forever
            # stood between it and a replay. Nonces are pruned now.
            if not body.get("created_at"):
                raise ValidationError("created_at is required")
            check_freshness(body["created_at"])
        except (ValidationError, KeyError) as exc:
            raise MandateError(f"invalid intent: {exc}") from exc

        if not verify_object(signed_intent, expected_did=signed_intent["agent_did"]):
            raise MandateError("intent signature invalid")

        intent = _intent_from_signed(signed_intent)
        receipt_id = new_id("rcpt")

        try:
            with self.ledger.tx() as tx:
                tx.audit("intent.received", {"intent_id": intent.id, "grant_id": intent.grant_id}, intent.id)
                # A grant of another tenant must be indistinguishable from
                # one that does not exist.
                grant_doc = tx.get_grant(intent.grant_id, tenant=tenant)
                if not grant_doc:
                    raise MandateError("unknown grant")
                if not verify_object(grant_doc, expected_did=grant_doc["principal_did"]):
                    tx.audit("intent.denied", {"reason": "grant signature invalid"}, intent.id)
                    raise MandateError("grant signature invalid")
                grant = _grant_from_doc(grant_doc)

                if not tx.consume_nonce(intent.audience, intent.nonce, receipt_id, tenant=tenant):
                    tx.audit("replay.rejected", {"nonce": intent.nonce, "audience": intent.audience}, intent.id)
                    raise MandateError("replay: nonce already used for this audience")

                agent_doc = tx.get_agent(intent.agent_did, tenant=tenant)
                if not agent_doc:
                    raise MandateError("unknown agent")

                spent = tx.spent(grant.id, intent.currency, self._day())
                decision = evaluate(grant, intent, spent_today_minor=spent)
                budget_day = None

                if decision.requires_human:
                    state = "HUMAN_REQUIRED"
                    tx.audit("intent.human_required", {"receipt_id": receipt_id}, intent.id)
                elif decision.allowed:
                    # An intent without an amount reserves nothing, so a
                    # malformed cap must not turn it into an error.
                    amt = amount_minor or 0
                    cap_minor = (
                        constraint_minor(grant.constraints, "max_daily_amount", intent.currency)
                        if intent.amount is not None
                        else None
                    )
                    budget_day = self._day()
                    if not tx.reserve(grant.id, intent.currency, budget_day, amt, cap_minor):
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
                if amount_minor is not None:
                    signed_body["amount_minor"] = amount_minor
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
                        "amount_minor": amount_minor,
                        "currency": intent.currency,
                        "state": state,
                        "execution_id": None,
                        "body": signed_receipt,
                        "budget_day": budget_day,
                        "tenant": tenant,
                    },
                    chain=self._chain(tx, tenant, receipt_id, state, signed_receipt),
                )
                return signed_receipt
        except StorageError as exc:
            raise MandateError("storage error") from exc
        except SigningError as exc:
            # Pre-existing gap this release would have made likelier: an
            # enforcer that cannot sign escaped `submit_intent` as a
            # SigningError, past callers that only handle MandateError.
            # Nothing has been dispatched here, so a refusal is the answer.
            raise MandateError("the receipt could not be signed") from exc
        except InvalidTransition as exc:
            raise MandateError(str(exc)) from exc
        except MandateError:
            raise
        except Exception as exc:
            raise MandateError("policy or internal error") from exc

    def get_receipt(self, receipt_id: str, tenant: str = DEFAULT_TENANT) -> dict | None:
        with self.ledger.tx() as tx:
            row = tx.get_receipt(receipt_id, tenant=tenant)
        if not row:
            return None
        body = json.loads(row["body"])
        if not verify_object(body, expected_did=self.enforcer_did):
            raise MandateError("receipt was not signed by this enforcer")
        return body

    def approve(
        self, receipt_id: str, principal_kp: Signer, approval: dict | None = None,
        tenant: str = DEFAULT_TENANT,
    ) -> dict[str, Any]:
        """Revalidate then HUMAN_REQUIRED -> AUTHORIZED. Never jumps to EXECUTED."""
        if approval is None:
            row_preview = None
            with self.ledger.tx() as tx:
                row_preview = tx.get_receipt(receipt_id, tenant=tenant)
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
        return self.submit_approval(approval, principal_kp.did(), tenant=tenant)

    def submit_approval(
        self, signed_approval: dict[str, Any], expected_principal: str | None = None,
        tenant: str = DEFAULT_TENANT,
    ) -> dict[str, Any]:
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
                row = tx.get_receipt(a["receipt_id"], tenant=tenant)
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

                grant_doc = tx.get_grant(body["grant_id"], tenant=tenant)
                if not grant_doc or not verify_object(grant_doc, expected_did=grant_doc["principal_did"]):
                    raise MandateError("grant signature invalid")
                grant = _grant_from_doc(grant_doc)
                intent = _intent_from_signed(intent_doc)
                spent = tx.spent(grant.id, intent.currency, self._day())
                decision = evaluate(grant, intent, spent_today_minor=spent, skip_human=True)
                if not decision.allowed:
                    new_body = {k: v for k, v in body.items() if k != "proof"}
                    new_body["decision"] = decision.to_dict()
                    new_body["outcome"] = "DENIED"
                    new_body["approval"] = signed_approval
                    signed = sign_object(self.enforcer, new_body)
                    if not tx.cas_state(
                        a["receipt_id"], "HUMAN_REQUIRED", "DENIED", signed,
                        chain=self._chain(tx, tenant, a["receipt_id"], "DENIED", signed),
                    ):
                        raise MandateError("invalid state transition")
                    tx.audit("approval.rejected", {"reason": decision.reasons}, a.get("approval_id"))
                    return signed

                try:
                    amt = intent_amount_minor(intent) or 0
                    cap_minor = (
                        constraint_minor(grant.constraints, "max_daily_amount", intent.currency)
                        if intent.amount is not None
                        else None
                    )
                except MoneyError as exc:
                    raise MandateError(f"inexact amount: {exc}") from exc
                budget_day = self._day()
                if not tx.reserve(grant.id, intent.currency, budget_day, amt, cap_minor):
                    new_body = {k: v for k, v in body.items() if k != "proof"}
                    new_body["decision"] = {"allowed": False, "reasons": ["budget reservation failed"], "requires_human": False}
                    new_body["outcome"] = "DENIED"
                    signed = sign_object(self.enforcer, new_body)
                    tx.cas_state(
                        a["receipt_id"], "HUMAN_REQUIRED", "DENIED", signed,
                        chain=self._chain(tx, tenant, a["receipt_id"], "DENIED", signed),
                    )
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
                if intent.amount is not None:
                    new_body["amount_minor"] = amt
                signed = sign_object(self.enforcer, new_body)
                if not tx.cas_state(
                    a["receipt_id"], "HUMAN_REQUIRED", "AUTHORIZED", signed,
                    chain=self._chain(tx, tenant, a["receipt_id"], "AUTHORIZED", signed),
                ):
                    raise MandateError("invalid state transition")
                tx.put_budget_binding(a["receipt_id"], grant.id, intent.currency, budget_day, amt)
                tx.set_receipt_budget_day(a["receipt_id"], budget_day)
                tx.audit("authorization.created", {"receipt_id": a["receipt_id"], "via": "approval", "day": budget_day}, a.get("approval_id"))
                return signed
        except StorageError as exc:
            raise MandateError("storage error") from exc

    def execute(
        self, receipt_id: str, idempotency_key: str | None = None,
        tenant: str = DEFAULT_TENANT,
    ) -> dict[str, Any]:
        if self.executor is None:
            raise MandateError("no executor configured")
        executor = self.executor

        try:
            with self.ledger.tx() as tx:
                row = tx.get_receipt(receipt_id, tenant=tenant)
                if not row:
                    raise MandateError("unknown receipt")
                existing = tx.get_execution_by_receipt(receipt_id)
                if existing:
                    if row["state"] == "EXECUTING" and self._is_stale(existing.get("started_at")):
                        return self._mark_unknown(tx, receipt_id, "reconciled: claim outlived its process")
                    return json.loads(row["body"])
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
                try:
                    amount_minor = intent_amount_minor(intent) or 0
                except MoneyError as exc:
                    raise MandateError(f"inexact amount: {exc}") from exc
                if row["amount_minor"] is not None and int(row["amount_minor"]) != amount_minor:
                    raise MandateError("receipt execution fields mismatch")
                grant_doc = tx.get_grant(body["grant_id"], tenant=tenant)
                if not grant_doc or not verify_object(grant_doc, expected_did=body["principal_did"]):
                    raise MandateError("grant signature invalid")
                grant = _grant_from_doc(grant_doc)
                if grant.id != intent.grant_id or grant.principal_did != body["principal_did"]:
                    raise MandateError("grant identity mismatch")
                binding = tx.get_budget_binding(receipt_id)
                if not binding:
                    raise MandateError("authorization lacks budget binding")
                if (binding["grant_id"], binding["currency"], binding["amount_minor"]) != (
                    intent.grant_id, intent.currency, amount_minor,
                ):
                    raise MandateError("budget binding mismatch")
                # The current reservation already counts toward this day's cap.
                spent = max(0, tx.spent(grant.id, intent.currency, binding["day"]) - binding["amount_minor"])
                approval = tx.get_approval_by_receipt(receipt_id)
                human_approved = False
                if approval and approval["consumed"]:
                    approval_body = json.loads(approval["body"])
                    human_approved = (
                        verify_object(approval_body, expected_did=body["principal_did"])
                        and approval_body.get("receipt_id") == receipt_id
                        and approval_body.get("intent_id") == intent.id
                    )
                decision = evaluate(grant, intent, spent_today_minor=spent, skip_human=human_approved)
                if not decision.allowed:
                    denied = {k: v for k, v in body.items() if k != "proof"}
                    denied.update(outcome="DENIED", decision=decision.to_dict())
                    signed = sign_object(self.enforcer, denied)
                    if not tx.cas_state(
                        receipt_id, "AUTHORIZED", "DENIED", signed,
                        chain=self._chain(tx, tenant, receipt_id, "DENIED", signed),
                    ):
                        raise MandateError("authorization already consumed")
                    tx.release_budget(grant.id, intent.currency, binding["day"], binding["amount_minor"])
                    tx.audit("execution.denied", {"receipt_id": receipt_id, "reasons": decision.reasons}, receipt_id)
                    return signed
                audience = row["audience"]
                route = self.routes.get(audience, tenant=row["tenant"])
                if route is None:
                    raise MandateError("unknown route")
                execution_id = new_id("exec")
                idem = idempotency_key or execution_id
                # Idempotency keys are caller-chosen, so they are stored under
                # a tenant-scoped form. Otherwise one tenant's key could return
                # another tenant's receipt.
                stored_idem = _scoped_idem(tenant, idem)
                prior = tx.get_execution_by_idem(stored_idem)
                if prior:
                    r2 = tx.get_receipt(prior["receipt_id"], tenant=tenant)
                    if r2 is None:
                        raise MandateError("idempotency key already used")
                    return json.loads(r2["body"])
                # The body is built and hashed before the claim, so the signed
                # receipt commits to the exact bytes that will be sent.
                operation = route.operation_for(intent.action)
                if route.operations and operation is None:
                    raise MandateError(f"no operation for action '{intent.action}'")
                try:
                    # None stays None here: an intent without an amount must
                    # not be reported to the upstream as a zero.
                    payload = build_payload(
                        operation, intent, execution_id,
                        amount_minor if intent.amount is not None else None,
                    )
                    request_body = encode(payload)
                except PayloadError as exc:
                    raise MandateError(f"invalid request payload: {exc}") from exc
                if operation is not None:
                    method, path = operation.method, operation.path
                else:
                    method, path = route.allowed_methods[0], route.allowed_paths[0]
                request_meta = {
                    "method": method,
                    "path": path,
                    "destination": route.base_url.rstrip("/") + path,
                    "hash": body_hash(request_body),
                    "size": len(request_body),
                }
                # The claim is signed as EXECUTING. If this process dies here,
                # the stored receipt states what actually happened instead of
                # still claiming AUTHORIZED.
                started = iso(self._now())
                claim = {k: v for k, v in body.items() if k != "proof"}
                claim["outcome"] = "EXECUTING"
                claim["execution"] = {
                    "execution_id": execution_id,
                    "state": "EXECUTING",
                    "idempotency_key": idem,
                    "enforcer_did": self.enforcer_did,
                    "predecessor_id": receipt_id,
                    "started_at": started,
                    "request": request_meta,
                }
                # Everything signed after dispatch must fit what the signer
                # can sign, or the outcome of a call that was made cannot be
                # recorded. That is decided now, while refusing costs nothing.
                cap = getattr(self.enforcer, "MAX_MESSAGE", None)
                if cap is not None:
                    size = len(canonical_json(_largest_outcome(claim)))
                    if size > cap:
                        return self._deny_unsendable(tx, tenant, receipt_id, body, size, cap)
                signed_claim = sign_object(self.enforcer, claim)
                if not tx.cas_state(
                    receipt_id, "AUTHORIZED", "EXECUTING", signed_claim,
                    chain=self._chain(tx, tenant, receipt_id, "EXECUTING", signed_claim),
                ):
                    raise MandateError("authorization already consumed")
                tx.set_execution(receipt_id, execution_id)
                tx.put_execution(
                    execution_id, receipt_id, stored_idem, "EXECUTING", {"started": started},
                    started_at=started,
                )
                tx.audit("execution.started", {"execution_id": execution_id, "receipt_id": receipt_id}, receipt_id)
        except StorageError as exc:
            raise MandateError("storage error") from exc
        except SigningError as exc:
            # Nothing has been dispatched: the claim is signed first precisely
            # so an unsignable execution never leaves the gateway. The detail
            # stays out of the message, which reaches a model as tool output.
            raise MandateError("the execution claim could not be signed") from exc

        try:
            result = executor.forward(route, method, path, request_body, idem)
        except Exception as exc:
            # The request may or may not have reached the upstream. Anything
            # other than EXECUTION_UNKNOWN would be a claim we cannot support.
            result = ExecutionResult(
                "EXECUTION_UNKNOWN", None, 0, None, f"executor error: {type(exc).__name__}"
            )

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
                    "started_at": started,
                    "request": request_meta,
                    "error": bounded_error(result.error),
                }
                signed = sign_object(self.enforcer, new_body)
                dst = result.state
                if not tx.cas_state(
                    receipt_id, "EXECUTING", dst, signed,
                    chain=self._chain(tx, tenant, receipt_id, dst, signed),
                ):
                    # Post-dispatch, losing this CAS means something else moved
                    # the receipt out of EXECUTING while the upstream call was
                    # in flight — normally the reconciler, which has already
                    # written EXECUTION_UNKNOWN. The call went out either way,
                    # so this is an unknown outcome, never a failed dispatch.
                    raise ExecutionUnknown(
                        "the call was dispatched but its outcome could not be recorded: "
                        "the receipt is no longer EXECUTING",
                        receipt_id,
                    )
                try:
                    gid, curr, day, bamt = self._settlement(tx, row, body)
                except MandateError as exc:
                    # Unreachable while execute() refuses an unbound receipt
                    # before dispatch; if it is ever reached, the call went out
                    # and the receipt stays EXECUTING for the reconciler.
                    raise ExecutionUnknown(
                        "the call was dispatched but the reservation it settles is not recorded",
                        receipt_id,
                    ) from exc
                if result.state == "EXECUTED":
                    tx.commit_budget(gid, curr, day, bamt)
                    tx.audit("execution.succeeded", {"execution_id": execution_id, "budget_day": day}, receipt_id)
                elif result.state == "EXECUTION_FAILED":
                    tx.release_budget(gid, curr, day, bamt)
                    tx.audit("execution.failed", {"execution_id": execution_id, "budget_day": day}, receipt_id)
                else:
                    tx.audit("execution.unknown", {"execution_id": execution_id, "budget_day": day}, receipt_id)
                tx.put_execution(
                    execution_id, receipt_id, stored_idem, result.state, new_body["execution"]
                )
                return signed
        except (StorageError, SigningError) as exc:
            # The request has already gone out. Failing to sign or store the
            # outcome says nothing about whether the upstream acted, so this
            # cannot be reported as a failed dispatch. The receipt stays
            # EXECUTING with its reservation held for the reconciler.
            raise ExecutionUnknown(
                "the call was dispatched but its outcome could not be recorded",
                receipt_id,
            ) from exc

    def _deny_unsendable(
        self, tx, tenant: str, receipt_id: str, body: dict, size: int, cap: int,
    ) -> dict[str, Any]:
        """AUTHORIZED -> DENIED before dispatch, releasing the reservation."""
        denied = {k: v for k, v in body.items() if k != "proof"}
        denied["outcome"] = "DENIED"
        denied["decision"] = {
            "allowed": False,
            "requires_human": False,
            "reasons": [
                f"the receipt could reach {size} bytes after dispatch and the enforcer "
                f"signer can sign at most {cap}; nothing was sent"
            ],
        }
        signed = sign_object(self.enforcer, denied)
        if not tx.cas_state(
            receipt_id, "AUTHORIZED", "DENIED", signed,
            chain=self._chain(tx, tenant, receipt_id, "DENIED", signed),
        ):
            raise MandateError("authorization already consumed")
        row = tx.get_receipt(receipt_id)
        gid, curr, day, amount = self._settlement(tx, row, body)
        tx.release_budget(gid, curr, day, amount)
        tx.audit("execution.refused", {"receipt_id": receipt_id, "size": size, "cap": cap}, receipt_id)
        return signed

    def _settlement(
        self, tx, row, body: dict, budget_day: str | None = None,
    ) -> tuple[str, str, str, int]:
        """The reservation a receipt's outcome settles: grant, currency, day
        and minor units.

        The binding written when the reservation was made is authoritative.
        Receipts from before bindings existed used to settle on *today* —
        the one day the reservation was certainly not made on whenever the
        settlement crosses midnight: a day that reserved nothing was debited
        and the real reservation stayed held. Such a receipt now settles on
        the day it records, or on the day an operator names; if neither
        exists, nothing is settled and the caller is told why. A day that was
        never written down cannot be recovered by guessing.
        """
        binding = tx.get_budget_binding(row["id"])
        recorded = binding["day"] if binding else (row.get("budget_day") or body.get("budget_day"))
        if budget_day is not None:
            try:
                datetime.strptime(budget_day, "%Y-%m-%d")
            except ValueError as exc:
                raise MandateError("budget day must be YYYY-MM-DD") from exc
            if recorded and budget_day != recorded:
                raise MandateError(f"this receipt reserved on {recorded}, not {budget_day}")
        day = recorded or budget_day
        if not day:
            raise MandateError(
                "this receipt predates budget bindings and records no reservation day; "
                "name the day it reserved"
            )
        if binding:
            return binding["grant_id"], binding["currency"], day, binding["amount_minor"]
        return row["grant_id"], row["currency"] or "EUR", day, int(row["amount_minor"] or 0)

    def unknown_receipts(self, tenant: str | None = None) -> list[dict[str, Any]]:
        """Receipts whose outcome nobody knows, for an operator to look into.

        Each one names what was sent and where, so the question "did the
        upstream act on it?" can be asked of the upstream, which is the only
        place it can be answered.
        """
        try:
            with self.ledger.tx() as tx:
                rows = tx.receipts_in_state("EXECUTION_UNKNOWN", tenant)
        except StorageError as exc:
            raise MandateError("storage error") from exc
        return [json.loads(r["body"]) | {"tenant": r["tenant"]} for r in rows]

    def resolve_unknown(
        self, receipt_id: str, outcome: str, *, operator: str, reason: str,
        tenant: str = DEFAULT_TENANT, budget_day: str | None = None,
    ) -> dict[str, Any]:
        """Record a human's finding about an EXECUTION_UNKNOWN receipt.

        The engine cannot know whether the upstream acted; a person who asked
        the upstream can. Their answer settles the reservation — committed if
        the call took effect, released if it did not — and becomes part of the
        receipt, signed and chained like every other state, with who decided
        and why. Until now the only way out of EXECUTION_UNKNOWN was to edit
        the database, which is exactly what the chain exists to catch.

        `budget_day` is needed only for a receipt from before budget bindings
        that records no reservation day; see `_settlement`.
        """
        if outcome not in {"EXECUTED", "EXECUTION_FAILED"}:
            raise MandateError("outcome must be EXECUTED or EXECUTION_FAILED")
        operator, reason = (operator or "").strip(), (reason or "").strip()
        if not operator or not reason:
            raise MandateError("a resolution needs the operator's name and a reason")
        if len(operator) > 200 or len(reason) > 2000:
            raise MandateError("operator is limited to 200 characters and reason to 2000")
        if any(not ch.isprintable() for ch in operator + reason.replace("\n", " ")):
            raise MandateError("operator and reason must be printable text")
        try:
            with self.ledger.tx() as tx:
                row = tx.get_receipt(receipt_id, tenant=tenant)
                if row is None:
                    raise MandateError("receipt not found")
                if row["state"] != "EXECUTION_UNKNOWN":
                    raise MandateError(f"receipt is {row['state']}, not EXECUTION_UNKNOWN")
                body = json.loads(row["body"])
                gid, curr, day, amount = self._settlement(tx, row, body, budget_day)
                new_body = {k: v for k, v in body.items() if k != "proof"}
                new_body["outcome"] = outcome
                execution = dict(new_body.get("execution") or {})
                execution["state"] = outcome
                execution["resolution"] = {
                    "from": "EXECUTION_UNKNOWN",
                    "decided": outcome,
                    "by": operator,
                    "reason": reason,
                    "at": iso(self._now()),
                    "budget_day": day,
                }
                new_body["execution"] = execution
                signed = sign_object(self.enforcer, new_body)
                if not tx.cas_state(
                    receipt_id, "EXECUTION_UNKNOWN", outcome, signed,
                    chain=self._chain(tx, row["tenant"], receipt_id, outcome, signed),
                ):
                    raise MandateError("receipt changed state while it was being resolved")
                if outcome == "EXECUTED":
                    tx.commit_budget(gid, curr, day, amount)
                else:
                    tx.release_budget(gid, curr, day, amount)
                prior = tx.get_execution_by_receipt(receipt_id)
                if prior:
                    tx.put_execution(
                        prior["id"], receipt_id, prior["idempotency_key"], outcome, execution
                    )
                tx.audit(
                    "execution.resolved",
                    {"receipt_id": receipt_id, "outcome": outcome, "by": operator, "budget_day": day},
                    receipt_id,
                )
                return signed
        except StorageError as exc:
            raise MandateError("storage error") from exc
        except SigningError as exc:
            # Operator-facing, so the signer's reason is useful here: a cap
            # is met by a shorter reason, which the pre-dispatch check keeps
            # room for.
            raise MandateError(f"the resolution could not be signed: {exc}") from exc

    def _is_stale(self, started_at: str | None) -> bool:
        cutoff = self._now() - timedelta(seconds=self.execution_stale_after_s)
        if not started_at:
            # A claim without a recorded start predates this column and cannot
            # be shown to be in flight.
            return True
        return started_at < iso(cutoff)

    def _mark_unknown(self, tx, receipt_id: str, reason: str) -> dict[str, Any]:
        """EXECUTING -> EXECUTION_UNKNOWN. The reservation is kept on purpose."""
        row = tx.get_receipt(receipt_id)
        body = json.loads(row["body"])
        new_body = {k: v for k, v in body.items() if k != "proof"}
        new_body["outcome"] = "EXECUTION_UNKNOWN"
        execution = dict(new_body.get("execution") or {})
        execution.update(
            state="EXECUTION_UNKNOWN", error=bounded_error(reason), reconciled_at=iso(self._now())
        )
        new_body["execution"] = execution
        signed = sign_object(self.enforcer, new_body)
        # Reconciliation sweeps every tenant, so the tenant comes off the row
        # rather than from a caller who may be closing out someone else's work.
        tenant = row["tenant"] if "tenant" in row.keys() else DEFAULT_TENANT
        if not tx.cas_state(
            receipt_id, "EXECUTING", "EXECUTION_UNKNOWN", signed,
            chain=self._chain(tx, tenant, receipt_id, "EXECUTION_UNKNOWN", signed),
        ):
            raise MandateError("invalid state transition")
        prior = tx.get_execution_by_receipt(receipt_id)
        if prior:
            tx.put_execution(
                prior["id"], receipt_id, prior["idempotency_key"], "EXECUTION_UNKNOWN", execution
            )
        tx.audit("execution.reconciled", {"receipt_id": receipt_id, "reason": reason}, receipt_id)
        return signed

    def reconcile_stale_executions(self, stale_after_s: int | None = None) -> list[str]:
        """Close out executions whose claiming process never came back.

        A receipt left in EXECUTING is not terminal and blocks its reservation
        forever. Whether the upstream saw the request is unknowable from here,
        so the honest terminal state is EXECUTION_UNKNOWN and the reservation
        stays held until a human reconciles it.
        """
        seconds = self.execution_stale_after_s if stale_after_s is None else stale_after_s
        cutoff = iso(self._now() - timedelta(seconds=seconds))
        reconciled: list[str] = []
        try:
            with self.ledger.tx() as tx:
                for stale in tx.stale_executions(cutoff):
                    self._mark_unknown(
                        tx, stale["receipt_id"], "reconciled: claim outlived its process"
                    )
                    reconciled.append(stale["receipt_id"])
        except StorageError as exc:
            raise MandateError("storage error") from exc
        return reconciled
