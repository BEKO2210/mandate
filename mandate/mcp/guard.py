"""The enforcement decision for one MCP tool call.

Synchronous and free of the MCP SDK on purpose: this is the part that decides
whether a call happens, so it is the part that has to be testable end to end
without a live protocol peer.

What the model gets back matters as much as the decision. A refusal names the
rule that refused, the grant it came from, and what would make the call
acceptable — an agent that is told only "denied" retries the same call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from ..auth import DEFAULT_TENANT
from ..crypto import sign_object
from ..engine import Engine, ExecutionUnknown, MandateError
from ..models import Intent
from ..signing import Signer, SigningError
from .mapping import MappingError, ToolMapping


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    text: str
    outcome: str
    receipt_id: str | None = None
    # For the operator's log, never for the model: a key manager's error can
    # name hosts, paths and ARNs, and `text` is tool output the model reads.
    detail: str | None = None

    def to_tool_result(self) -> dict[str, Any]:
        """Shape an MCP tool result: refusals are errors, not silent successes."""
        return {"isError": not self.allowed, "text": self.text}


class McpGuard:
    def __init__(
        self,
        engine: Engine,
        agent_signer: Signer | None,
        grant_id: str,
        mapping: ToolMapping,
        tenant: str = DEFAULT_TENANT,
        executor=None,
    ) -> None:
        self.engine = engine
        self.agent_signer = agent_signer
        self.grant_id = grant_id
        self.mapping = mapping
        self.tenant = tenant
        # The upstream response is collected from the executor, so it never
        # has to travel inside the signed receipt.
        self.executor = executor if executor is not None else getattr(engine, "executor", None)

    def call(self, tool: str, arguments: dict[str, Any] | None = None) -> GuardDecision:
        try:
            fields = self.mapping.intent_fields(tool, arguments)
        except MappingError as exc:
            return GuardDecision(False, f"Mandate refused this call: {exc}", "UNMAPPED")

        try:
            # Both of these reach the key manager when the key is not local:
            # naming the agent needs its DID, and signing needs the key itself.
            intent = Intent.create(
                agent_did=self.agent_signer.did(),
                grant_id=self.grant_id,
                nonce=uuid4().hex,
                **fields,
            )
            signed = sign_object(self.agent_signer, intent.to_dict())
        except SigningError as exc:
            # The key manager is unreachable or holds a different key. Refusing
            # is the only safe answer: an unsigned intent must never be
            # dispatched, and a call nobody can attribute is worse than none.
            # What went wrong goes to the operator; the model is told only that
            # retrying will not help, which is the part it can act on.
            return GuardDecision(
                False,
                "Mandate could not sign this call, so nothing was dispatched. "
                "The signing key is unavailable — this is an operator problem, "
                "not a limit of the grant, and retrying will not clear it.",
                "SIGNER_UNAVAILABLE",
                detail=str(exc),
            )

        try:
            receipt = self.engine.submit_intent(signed, tenant=self.tenant)
        except MandateError as exc:
            return GuardDecision(
                False,
                f"Mandate refused this call: {exc}. The grant is {self.grant_id}.",
                "REFUSED",
            )

        outcome = receipt.get("outcome")
        receipt_id = receipt.get("id")
        if outcome == "DENIED":
            reasons = "; ".join(receipt.get("decision", {}).get("reasons") or ["denied"])
            return GuardDecision(
                False,
                f"Mandate denied this call: {reasons}. This is a limit of grant "
                f"{self.grant_id}, not of the tool. Receipt {receipt_id}.",
                outcome,
                receipt_id,
            )
        if outcome == "HUMAN_REQUIRED":
            reasons = "; ".join(receipt.get("decision", {}).get("reasons") or [])
            # Addressed to the model, which in Claude Code or Cursor may have a
            # shell. It is told to ask the user, not how to approve: the
            # approval belongs to the principal, never to the agent it limits.
            return GuardDecision(
                False,
                f"Mandate is holding this call for human approval: {reasons}. "
                f"Receipt {receipt_id} is waiting. Tell the user that this call needs "
                f"their approval; once they approve it, it runs exactly once. Do not "
                f"retry the tool — a retry is a second request — and do not approve it "
                f"yourself.",
                outcome,
                receipt_id,
            )
        if outcome != "AUTHORIZED":
            return GuardDecision(
                False, f"Mandate returned an unexpected state {outcome}.", str(outcome), receipt_id
            )
        return self._dispatch(receipt_id)

    def approve(self, receipt_id: str, principal_signer: Signer) -> GuardDecision:
        """A held call, approved by its principal, runs now — once.

        The engine revalidates on approval: a grant revoked or a budget used up
        while the call waited turns the approval into a denial, and nothing is
        dispatched.
        """
        try:
            approved = self.engine.approve(receipt_id, principal_signer, tenant=self.tenant)
        except (MandateError, SigningError) as exc:
            return GuardDecision(False, f"Approval refused: {exc}.", "REFUSED", receipt_id)
        outcome = approved.get("outcome")
        if outcome != "AUTHORIZED":
            reasons = "; ".join(approved.get("decision", {}).get("reasons") or [str(outcome)])
            return GuardDecision(
                False,
                f"Approved, but revalidation denied it: {reasons}. Nothing was dispatched.",
                str(outcome),
                receipt_id,
            )
        return self._dispatch(receipt_id)

    def resume(self, receipt_id: str) -> GuardDecision:
        """Dispatch a call that was approved but never started.

        The execution claim in `Engine.execute` is what keeps it to once: a
        receipt already claimed is reported, not dispatched again.
        """
        return self._dispatch(receipt_id)

    def _dispatch(self, receipt_id: str) -> GuardDecision:
        """Execute an AUTHORIZED receipt and say what happened."""
        idem = uuid4().hex
        try:
            executed = self.engine.execute(receipt_id, idempotency_key=idem, tenant=self.tenant)
        except ExecutionUnknown as exc:
            # The call went out. Saying "could not dispatch" here would invite
            # exactly the retry that must not happen.
            return GuardDecision(
                False,
                f"The tool call was dispatched but its outcome could not be recorded. "
                f"Receipt {exc.receipt_id or receipt_id} stays open and its budget stays "
                f"reserved. Do not retry blindly — check whether the action took effect.",
                "EXECUTION_UNKNOWN",
                exc.receipt_id or receipt_id,
                detail=str(exc.__cause__ or exc),
            )
        except MandateError as exc:
            return GuardDecision(
                False,
                f"Mandate authorized this call but could not dispatch it: {exc}. "
                f"Receipt {receipt_id}.",
                "DISPATCH_FAILED",
                receipt_id,
            )

        final = executed.get("outcome")
        execution = executed.get("execution") or {}
        take = getattr(self.executor, "take_payload", None)
        payload = take(idem) if callable(take) else None
        if final == "EXECUTED":
            body = payload if isinstance(payload, str) and payload else "(no content)"
            return GuardDecision(True, body, final, receipt_id)
        if final == "EXECUTION_UNKNOWN":
            return GuardDecision(
                False,
                f"The tool call was dispatched but its outcome is unknown "
                f"({execution.get('error') or 'no response'}). Receipt {receipt_id} records "
                f"this and its budget stays reserved. Do not retry blindly — check whether "
                f"the action took effect.",
                final,
                receipt_id,
            )
        detail = payload if isinstance(payload, str) and payload else execution.get("error")
        return GuardDecision(
            False,
            f"The tool reported a failure: {detail or 'no detail'}. Receipt {receipt_id}.",
            str(final),
            receipt_id,
        )
