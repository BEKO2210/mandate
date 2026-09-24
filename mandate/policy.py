from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import Decision, Grant, Intent
from .money import MoneyError, format_minor, to_minor


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def intent_amount_minor(intent: Intent) -> int | None:
    """Exact minor-unit amount of a signed intent, derived deterministically."""
    if intent.amount is None:
        return None
    return to_minor(intent.amount, intent.currency)


def constraint_minor(constraints: dict[str, Any], key: str, currency: str) -> int | None:
    value = (constraints or {}).get(key)
    if value is None:
        return None
    return to_minor(value, currency)


def evaluate(
    grant: Grant,
    intent: Intent,
    spent_today_minor: int = 0,
    skip_human: bool = False,
    allowed_audiences: list[str] | None = None,
) -> Decision:
    """Judge an intent against a grant's scopes, budget, and counterparty rules."""
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

    grant_audiences = (grant.constraints or {}).get("audiences") or allowed_audiences
    if grant_audiences and intent.audience not in grant_audiences:
        reasons.append(f"audience '{intent.audience}' not permitted by grant")

    c: dict[str, Any] = grant.constraints or {}
    currency = c.get("currency") or "EUR"
    amount_minor: int | None = None
    human_minor: int | None = None
    if intent.amount is not None:
        try:
            # Constraint and intent are only comparable in the same currency,
            # so a mismatch is decided before any conversion is trusted.
            if intent.currency != currency:
                reasons.append(f"currency {intent.currency} != {currency}")
            else:
                amount_minor = intent_amount_minor(intent)
                max_minor = constraint_minor(c, "max_amount", currency)
                daily_minor = constraint_minor(c, "max_daily_amount", currency)
                human_minor = constraint_minor(c, "require_human_above", currency)
                if max_minor is not None and amount_minor > max_minor:
                    reasons.append(
                        f"amount {format_minor(amount_minor, currency)} exceeds max_amount "
                        f"{format_minor(max_minor, currency)}"
                    )
                if daily_minor is not None and spent_today_minor + amount_minor > daily_minor:
                    reasons.append(
                        f"amount would exceed daily cap {format_minor(daily_minor, currency)} "
                        f"(already spent {format_minor(spent_today_minor, currency)})"
                    )
        except MoneyError as exc:
            # An amount or constraint that is not exactly representable must
            # never be rounded into a budget decision. Fail closed.
            return Decision(False, [f"inexact amount: {exc}"], grant_id=grant.id, intent_id=intent.id)

    allow = c.get("counterparties_allow") or []
    deny = c.get("counterparties_deny") or []
    if intent.counterparty:
        if deny and intent.counterparty in deny:
            reasons.append(f"counterparty {intent.counterparty} is denied")
        if allow and intent.counterparty not in allow:
            reasons.append(f"counterparty {intent.counterparty} not in allow-list")
    elif allow and intent.amount is not None:
        # An allow-list names who may be paid, so a payment that names no
        # payee is not a way past it. A call that moves no money — reading a
        # catalogue — pays nobody, and is not the list's to refuse. (A
        # deny-list cannot say "unknown is bad", so it stays consulted only
        # when there is a name to consult it with.)
        reasons.append("counterparty required by the grant's allow-list")

    requires_human = False
    if (
        not skip_human
        and amount_minor is not None
        and human_minor is not None
        and amount_minor > human_minor
        and not reasons
    ):
        requires_human = True
        reasons.append(
            f"amount {format_minor(amount_minor, currency)} requires human approval above "
            f"{format_minor(human_minor, currency)}"
        )

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
