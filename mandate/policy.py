from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import Decision, Grant, Intent


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def evaluate(grant: Grant, intent: Intent, spent_today: float = 0.0) -> Decision:
    reasons: list[str] = []
    now = datetime.now(timezone.utc)

    if grant.status != "active":
        return Decision(False, [f"grant status is {grant.status}"], grant_id=grant.id, intent_id=intent.id)
    if intent.agent_did != grant.agent_did:
        return Decision(False, ["intent agent does not match grant agent"], grant_id=grant.id, intent_id=intent.id)
    if now < _parse(grant.not_before):
        reasons.append("grant not yet valid")
    if now > _parse(grant.not_after):
        reasons.append("grant expired")
    if intent.action not in grant.scopes and not _scope_matches(intent.action, grant.scopes):
        reasons.append(f"action '{intent.action}' is outside scopes {grant.scopes}")

    c: dict[str, Any] = grant.constraints or {}
    amount = intent.amount
    if amount is not None:
        currency = c.get("currency") or "EUR"
        if intent.currency != currency:
            reasons.append(f"currency {intent.currency} != {currency}")
        if c.get("max_amount") is not None and amount > float(c["max_amount"]):
            reasons.append(f"amount {amount} exceeds max_amount {c['max_amount']}")
        if c.get("max_daily_amount") is not None and spent_today + amount > float(c["max_daily_amount"]):
            reasons.append(f"amount would exceed daily cap {c['max_daily_amount']} (already spent {spent_today})")

    allow = c.get("counterparties_allow") or []
    deny = c.get("counterparties_deny") or []
    if intent.counterparty:
        if deny and intent.counterparty in deny:
            reasons.append(f"counterparty {intent.counterparty} is denied")
        if allow and intent.counterparty not in allow:
            reasons.append(f"counterparty {intent.counterparty} not in allow-list")

    requires_human = False
    threshold = c.get("require_human_above")
    if amount is not None and threshold is not None and amount > float(threshold) and not reasons:
        requires_human = True
        reasons.append(f"amount {amount} requires human approval above {threshold}")

    hard_fail = [r for r in reasons if "requires human" not in r]
    if hard_fail:
        return Decision(False, reasons, requires_human=False, grant_id=grant.id, intent_id=intent.id)
    if requires_human:
        return Decision(False, reasons, requires_human=True, grant_id=grant.id, intent_id=intent.id)
    return Decision(True, ["ok"], requires_human=False, grant_id=grant.id, intent_id=intent.id)


def _scope_matches(action: str, scopes: list[str]) -> bool:
    for s in scopes:
        if s.endswith(".*") and action.startswith(s[:-2] + "."):
            return True
        if s == "*":
            return True
    return False
