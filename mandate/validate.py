"""Untrusted input hardening."""

from __future__ import annotations

import re
from typing import Any

from .crypto import canonical_json, utcnow
from .money import MoneyError, require_minor, to_minor

AUDIENCE_RE = re.compile(r"^mandate://[a-z0-9][a-z0-9._-]{0,63}$")
ACTION_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
ID_RE = re.compile(r"^[a-z]+_[0-9a-f]{8,32}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
DID_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$")
NONCE_RE = re.compile(r"^[0-9a-f]{16,128}$")

MAX_BODY = 32_768
MAX_SUMMARY = 256
MAX_CONTEXT_BYTES = 2048
FORBIDDEN_KEYS = frozenset(
    {
        "target_url",
        "destination_url",
        "host",
        "base_url",
        "proxy_url",
        "url",
        "upstream",
        "redirect_url",
        "network_policy",
        "allow_private",
    }
)


class ValidationError(Exception):
    pass


def reject_forbidden(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise ValidationError(f"forbidden field {k}")
            reject_forbidden(v, path + "." + str(k))
    elif isinstance(obj, list):
        if len(obj) > 32:
            raise ValidationError("list too long")
        for i, v in enumerate(obj):
            reject_forbidden(v, f"{path}[{i}]")


def require_audience(value: str) -> str:
    if not isinstance(value, str) or not AUDIENCE_RE.match(value):
        raise ValidationError("invalid audience")
    return value


def require_action(value: str) -> str:
    if not isinstance(value, str) or not ACTION_RE.match(value):
        raise ValidationError("invalid action")
    return value


def require_nonce(value: str) -> str:
    if not isinstance(value, str) or not NONCE_RE.match(value):
        raise ValidationError("invalid nonce")
    return value


def require_currency(value: str) -> str:
    if not isinstance(value, str) or not CURRENCY_RE.match(value):
        raise ValidationError("invalid currency")
    return value


def require_amount(value: Any, currency: str = "EUR") -> int | None:
    """Validate a wire amount and return it in exact integer minor units."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError("invalid amount")
    try:
        return to_minor(value, currency)
    except MoneyError as exc:
        raise ValidationError(f"invalid amount: {exc}") from exc


def require_amount_agreement(body: dict[str, Any], amount_minor: int | None) -> None:
    """An explicitly supplied amount_minor must match the decimal amount."""
    declared = body.get("amount_minor")
    if declared is None:
        return
    try:
        declared = require_minor(declared)
    except MoneyError as exc:
        raise ValidationError(str(exc)) from exc
    if amount_minor is None or declared != amount_minor:
        raise ValidationError("amount_minor does not match amount")


def require_context(context: Any) -> dict[str, Any]:
    """Bound the agent-supplied context.

    MAX_CONTEXT_BYTES was declared from the start but never checked, so the
    only thing limiting an intent's context was the 32 KiB body cap. It is
    enforced here, against the canonical bytes that get signed.
    """
    if context is None:
        return {}
    if not isinstance(context, dict):
        raise ValidationError("context must be an object")
    size = len(canonical_json(context))
    if size > MAX_CONTEXT_BYTES:
        raise ValidationError(f"context is {size} bytes, limit is {MAX_CONTEXT_BYTES}")
    return context


def require_did(value: str) -> str:
    if not isinstance(value, str) or not DID_RE.match(value):
        raise ValidationError("invalid did")
    return value


#: How old an intent may be, and how far ahead of this clock it may claim to
#: be. Together they bound how long a signed intent can be replayed, and so
#: how long its nonce has to be remembered (see `NONCE_RETENTION_S`).
INTENT_MAX_AGE_S = 300
CLOCK_SKEW_S = 30
#: A nonce consumed at t belongs to an intent created no later than t + skew,
#: which is stale from t + skew + max age on. A minute of margin on top.
NONCE_RETENTION_S = INTENT_MAX_AGE_S + CLOCK_SKEW_S + 60


def check_freshness(created_at: str, max_age_s: int = INTENT_MAX_AGE_S, what: str = "intent") -> None:
    from datetime import datetime, timezone

    try:
        ts = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception as exc:
        raise ValidationError("invalid timestamp") from exc
    age = (utcnow() - ts).total_seconds()
    if age > max_age_s or age < -CLOCK_SKEW_S:
        raise ValidationError(f"{what} not fresh")
