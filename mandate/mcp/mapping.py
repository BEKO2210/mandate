"""Translate an MCP tool call into a signed Mandate intent.

The agent picks a tool and its arguments. This module decides, from
server-side configuration, which action that call counts as and which of its
arguments carry money. Nothing here trusts the tool name or the arguments to
mean what they claim.

Arguments never enter the intent as named fields. They travel as one canonical
JSON string under `arguments_json`, because an MCP tool may legitimately take
an argument called `url` or `host` — names the intent validator forbids
anywhere in a signed object. Carrying them as an opaque document keeps that
guard intact and still binds the exact bytes into the receipt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..crypto import canonical_json
from ..routes import Operation
from ..validate import ACTION_RE, AUDIENCE_RE, MAX_CONTEXT_BYTES, MAX_SUMMARY

# Room for the other context keys and JSON punctuation.
MAX_ARGUMENTS_JSON = MAX_CONTEXT_BYTES - 256

_UNSAFE_ACTION_CHARS = re.compile(r"[^a-z0-9_.]")


class MappingError(ValueError):
    pass


def normalize_action(tool: str) -> str:
    """Derive a policy action from a tool name, or fail loudly."""
    candidate = _UNSAFE_ACTION_CHARS.sub("_", (tool or "").strip().lower())[:64]
    candidate = candidate.lstrip("_.")
    if not candidate or not ACTION_RE.match(candidate):
        raise MappingError(f"cannot derive an action from tool name {tool!r}")
    return candidate


@dataclass(frozen=True)
class ToolRule:
    """What one MCP tool means in policy terms."""

    action: str
    amount_from: str | None = None
    currency_from: str | None = None
    currency: str = "EUR"
    counterparty_from: str | None = None

    def __post_init__(self) -> None:
        if not ACTION_RE.match(self.action or ""):
            raise MappingError(f"invalid action {self.action!r}")


@dataclass
class ToolMapping:
    audience: str
    rules: dict[str, ToolRule] = field(default_factory=dict)
    # An unmapped tool is refused. Enforcement that silently passes what it
    # was never configured for is not enforcement.
    allow_unmapped: bool = False

    def __post_init__(self) -> None:
        if not AUDIENCE_RE.match(self.audience or ""):
            raise MappingError(
                f"invalid audience {self.audience!r}; expected mandate://<name>"
            )

    def rule_for(self, tool: str) -> ToolRule:
        rule = self.rules.get(tool)
        if rule is not None:
            return rule
        if not self.allow_unmapped:
            raise MappingError(
                f"tool {tool!r} is not mapped to an action; add it to the guard "
                f"configuration or set allow_unmapped"
            )
        return ToolRule(action=normalize_action(tool))

    def intent_fields(self, tool: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        """Policy-relevant fields for one call. Raises rather than guessing."""
        rule = self.rule_for(tool)
        args = arguments or {}
        if not isinstance(args, dict):
            raise MappingError("tool arguments must be an object")

        encoded = canonical_json(args).decode("utf-8")
        if len(encoded.encode("utf-8")) > MAX_ARGUMENTS_JSON:
            raise MappingError(
                f"arguments are larger than the {MAX_ARGUMENTS_JSON} byte limit for a "
                f"signed intent; call {tool!r} with less data"
            )

        fields: dict[str, Any] = {
            "action": rule.action,
            "audience": self.audience,
            "summary": _summary(tool, args),
            "context": {"tool": tool, "arguments_json": encoded},
        }
        if rule.amount_from is not None:
            fields["amount"] = _amount(args, rule.amount_from, tool)
            fields["currency"] = _currency(args, rule)
        if rule.counterparty_from is not None:
            fields["counterparty"] = _counterparty(args, rule.counterparty_from)
        return fields

    def operation_for(self, tool: str) -> Operation:
        """The server-side contract for forwarding this tool call."""
        rule = self.rule_for(tool)
        return Operation(
            action=rule.action,
            # MCP has no request methods. POST is a placeholder so the route
            # allowlists keep their existing shape.
            method="POST",
            path="/" + tool,
            fields=("action", "execution_id"),
            context_fields=("tool", "arguments_json"),
            max_string=MAX_ARGUMENTS_JSON,
        )


def _summary(tool: str, args: dict[str, Any]) -> str:
    keys = ", ".join(sorted(args)[:6])
    text = f"MCP tool {tool}({keys})" if keys else f"MCP tool {tool}()"
    return text[:MAX_SUMMARY]


def _amount(args: dict[str, Any], key: str, tool: str) -> float | int:
    if key not in args:
        raise MappingError(
            f"tool {tool!r} is configured with amount_from={key!r} but the call "
            f"did not provide it"
        )
    value = args[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        # A string amount would have to be parsed, and a parse is a guess.
        raise MappingError(
            f"argument {key!r} must be a number to be treated as an amount, got "
            f"{type(value).__name__}"
        )
    return value


def _currency(args: dict[str, Any], rule: ToolRule) -> str:
    if rule.currency_from is None:
        return rule.currency
    value = args.get(rule.currency_from)
    if not isinstance(value, str) or not value:
        raise MappingError(f"argument {rule.currency_from!r} must be a currency code")
    return value.upper()


def _counterparty(args: dict[str, Any], key: str) -> str:
    # Configured means required: a call that leaves its counterparty out
    # would otherwise be judged as if it named none, and an allow-list is
    # not a question the call gets to skip.
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise MappingError(
            f"argument {key!r} is configured as the counterparty and must be a "
            f"non-empty string"
        )
    if len(value) > MAX_SUMMARY:
        # Cut to fit, the value judged would not be the value sent upstream.
        raise MappingError(f"argument {key!r} is longer than {MAX_SUMMARY} characters")
    return value
