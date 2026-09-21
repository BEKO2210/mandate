"""Upstream request bodies are built here, server-side, and then hashed.

The agent signs an intent; it does not compose the bytes that leave the
gateway. An Operation names which intent fields may appear in the body, this
module fills exactly those, and the enforcer signs the hash of the resulting
bytes *before* the request is sent. A receipt therefore states what was sent,
not merely what was authorized.
"""

from __future__ import annotations

import math
from typing import Any

from .crypto import canonical_json, sha256_hex
from .models import Intent
from .routes import Operation

MAX_STRING = 256
MAX_BODY_BYTES = 8192


class PayloadError(ValueError):
    pass


def _scalar(value: Any, where: str) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PayloadError(f"{where} is not a finite number")
        return value
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise PayloadError(f"{where} exceeds {MAX_STRING} characters")
        return value
    # Nested structures would let an agent smuggle shapes the operation never
    # declared, so only scalars cross the boundary.
    raise PayloadError(f"{where} must be a scalar")


def _intent_value(name: str, intent: Intent, execution_id: str, amount_minor: int | None) -> Any:
    if name == "execution_id":
        return execution_id
    if name == "intent_id":
        return intent.id
    if name == "amount_minor":
        return amount_minor
    return getattr(intent, name)


def build_payload(
    operation: Operation | None,
    intent: Intent,
    execution_id: str,
    amount_minor: int | None = None,
) -> dict[str, Any]:
    if operation is None:
        # Pre-0.3 routes without declared operations keep their exact body.
        return {
            "action": intent.action,
            "amount": intent.amount,
            "currency": intent.currency,
            "execution_id": execution_id,
        }

    payload: dict[str, Any] = {}
    for name in operation.fields:
        payload[name] = _scalar(
            _intent_value(name, intent, execution_id, amount_minor), f"field {name}"
        )

    context = intent.context or {}
    for key in operation.context_fields:
        if key not in context:
            # A declared field is part of the operation's contract. Guessing a
            # default here would send the upstream something nobody signed.
            raise PayloadError(f"context field {key} is required by this operation")
        payload[key] = _scalar(context[key], f"context field {key}")
    return payload


def encode(payload: dict[str, Any]) -> bytes:
    body = canonical_json(payload)
    if len(body) > MAX_BODY_BYTES:
        raise PayloadError("request body too large")
    return body


def body_hash(body: bytes) -> str:
    return "sha256:" + sha256_hex(body)
