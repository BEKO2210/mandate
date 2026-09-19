from __future__ import annotations
import re
from typing import Any
from .crypto import utcnow

AUDIENCE_RE = re.compile(r"^mandate://[a-z0-9][a-z0-9._-]{0,63}$")
ACTION_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
DID_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$")
NONCE_RE = re.compile(r"^[0-9a-f]{16,128}$")
MAX_BODY = 32768
FORBIDDEN_KEYS = frozenset({"target_url","destination_url","host","base_url","proxy_url","url","upstream","redirect_url"})

class ValidationError(Exception):
    pass

def reject_forbidden(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise ValidationError(f"forbidden field {k}")
            reject_forbidden(v, path + "." + str(k))
    elif isinstance(obj, list):
        if len(obj) > 32:
            raise ValidationError("list too long")
        for v in obj:
            reject_forbidden(v, path)

def require_audience(value):
    if not isinstance(value, str) or not AUDIENCE_RE.match(value):
        raise ValidationError("invalid audience")
    return value

def require_action(value):
    if not isinstance(value, str) or not ACTION_RE.match(value):
        raise ValidationError("invalid action")
    return value

def require_nonce(value):
    if not isinstance(value, str) or not NONCE_RE.match(value):
        raise ValidationError("invalid nonce")
    return value

def require_currency(value):
    if not isinstance(value, str) or not CURRENCY_RE.match(value):
        raise ValidationError("invalid currency")
    return value

def require_amount(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError("invalid amount")
    if value < 0 or value > 1_000_000_000:
        raise ValidationError("invalid amount")
    return float(value)

def require_did(value):
    if not isinstance(value, str) or not DID_RE.match(value):
        raise ValidationError("invalid did")
    return value

def check_freshness(created_at, max_age_s=300):
    from datetime import datetime, timezone
    try:
        ts = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception as exc:
        raise ValidationError("invalid timestamp") from exc
    age = (utcnow() - ts).total_seconds()
    if age > max_age_s or age < -30:
        raise ValidationError("intent not fresh")
