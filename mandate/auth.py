"""Transport authentication, tenancy and rate limiting for the gateway.

Signed objects prove who authored a grant or an intent. They do not say who is
allowed to *reach* the gateway, and they cannot stop a stranger from flooding
it or from reading another customer's receipts. That is this module's job.

An API key is presented as `Authorization: Bearer mk_<id>_<secret>`. Only the
SHA-256 of the secret is stored. A plain hash is the right primitive here: the
secret is 256 bits from `secrets.token_urlsafe`, so there is no dictionary to
attack and no reason to pay a password-hashing cost per request.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping

from .crypto import iso, utcnow

DEFAULT_TENANT = "default"

SCOPE_INTENTS_WRITE = "intents:write"
SCOPE_APPROVALS_WRITE = "approvals:write"
SCOPE_RECEIPTS_READ = "receipts:read"
SCOPE_ALL = "*"

KNOWN_SCOPES = frozenset(
    {SCOPE_INTENTS_WRITE, SCOPE_APPROVALS_WRITE, SCOPE_RECEIPTS_READ, SCOPE_ALL}
)

KEY_PREFIX = "mk"
_SECRET_BYTES = 32


class AuthError(Exception):
    """Raised when a request may not proceed. `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


class RateLimited(AuthError):
    def __init__(self, retry_after: float) -> None:
        super().__init__("rate limit exceeded", status=429)
        self.retry_after = retry_after


@dataclass(frozen=True)
class AuthContext:
    """Who is calling, and on whose data."""

    tenant: str
    key_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    def allows(self, scope: str) -> bool:
        return SCOPE_ALL in self.scopes or scope in self.scopes

    def require(self, scope: str) -> None:
        if not self.allows(scope):
            # The credential is valid; it just may not do this.
            raise AuthError(f"key is not permitted to {scope}", status=403)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def new_key_material() -> tuple[str, str, str]:
    """Return (token, key_id, secret_hash). The token is shown once, never stored."""
    key_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    return f"{KEY_PREFIX}_{key_id}_{secret}", key_id, hash_secret(secret)


def parse_token(token: str) -> tuple[str, str]:
    # The secret is urlsafe base64 and may itself contain "_", so the split is
    # bounded rather than greedy.
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != KEY_PREFIX or not parts[1] or not parts[2]:
        raise AuthError("malformed api key")
    return parts[1], parts[2]


def bearer_from_headers(headers: Mapping[str, str]) -> str:
    raw = headers.get("authorization") or headers.get("Authorization")
    if not raw:
        raise AuthError("missing bearer token")
    scheme, _, value = raw.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise AuthError("unsupported authorization scheme")
    return value.strip()


def normalize_scopes(scopes: Iterable[str]) -> frozenset[str]:
    out = {s.strip() for s in scopes if s and s.strip()}
    unknown = out - KNOWN_SCOPES
    if unknown:
        raise ValueError(f"unknown scopes {sorted(unknown)}")
    return frozenset(out)


class Authenticator:
    def authenticate(self, headers: Mapping[str, str]) -> AuthContext:
        raise NotImplementedError


class OpenAccess(Authenticator):
    """No authentication. Single-tenant development only.

    It has to be passed explicitly, so no deployment ends up unauthenticated
    by forgetting an argument.
    """

    def __init__(self, tenant: str = DEFAULT_TENANT) -> None:
        self.tenant = tenant

    def authenticate(self, headers: Mapping[str, str]) -> AuthContext:
        return AuthContext(tenant=self.tenant, key_id="open", scopes=frozenset({SCOPE_ALL}))


class LedgerApiKeyAuth(Authenticator):
    """API keys held in the ledger, verified in constant time."""

    def __init__(self, ledger, clock=utcnow) -> None:
        self.ledger = ledger
        self.clock = clock

    def authenticate(self, headers: Mapping[str, str]) -> AuthContext:
        token = bearer_from_headers(headers)
        key_id, secret = parse_token(token)
        with self.ledger.tx() as tx:
            row = tx.get_api_key(key_id)
        # Compare even when the key is unknown, so a missing key and a wrong
        # secret take the same path.
        expected = row["secret_hash"] if row else hash_secret("")
        ok = hmac.compare_digest(expected, hash_secret(secret))
        if not row or not ok:
            raise AuthError("invalid api key")
        if row["disabled"]:
            raise AuthError("api key is disabled")
        if row["expires_at"]:
            expires = datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            if self.clock() > expires:
                raise AuthError("api key expired")
        return AuthContext(
            tenant=row["tenant"],
            key_id=key_id,
            scopes=frozenset((row["scopes"] or "").split(",")) - {""},
        )


def issue_api_key(
    ledger,
    tenant: str,
    name: str,
    scopes: Iterable[str] = (SCOPE_ALL,),
    expires_at: datetime | None = None,
) -> tuple[str, str]:
    """Create a key and return (token, key_id). The token is never recoverable."""
    if not tenant or not name:
        raise ValueError("tenant and name are required")
    allowed = normalize_scopes(scopes)
    token, key_id, secret_hash = new_key_material()
    with ledger.tx() as tx:
        tx.put_api_key(
            key_id=key_id,
            tenant=tenant,
            name=name,
            secret_hash=secret_hash,
            scopes=",".join(sorted(allowed)),
            created_at=iso(utcnow()),
            expires_at=iso(expires_at) if expires_at else None,
        )
        tx.audit("apikey.issued", {"key_id": key_id, "tenant": tenant, "name": name})
    return token, key_id


class RateLimiter:
    """Token bucket per key, held in this process's memory.

    It bounds one process. Behind N workers the effective limit is N times the
    configured one, which is why the gateway defaults to `LedgerRateLimiter`.
    This one remains for embedding the engine where there is only one process
    by construction.
    """

    def __init__(self, per_minute: int = 120, burst: int | None = None, clock=time.monotonic) -> None:
        if per_minute <= 0:
            raise ValueError("per_minute must be positive")
        self.rate = per_minute / 60.0
        self.capacity = float(burst if burst is not None else per_minute)
        self.clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}

    def check(self, key: str) -> None:
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                retry_after = (1.0 - tokens) / self.rate
                self._buckets[key] = (tokens, now)
                raise RateLimited(retry_after)
            self._buckets[key] = (tokens - 1.0, now)


class LedgerRateLimiter:
    """Token bucket per key, held in the ledger.

    Every gateway process that serves one ledger shares one bucket per key,
    so the limit is what was configured regardless of how many workers run.
    Each check is one short `BEGIN IMMEDIATE` transaction, which serialises
    it against the other processes the same way budget reservations are.

    The clock is wall time because monotonic clocks are not comparable across
    processes. A clock that steps backwards refills nothing (see
    `take_rate_token`). If the ledger cannot be written the check raises, and
    the request fails rather than passing unmetered.
    """

    def __init__(self, ledger, per_minute: int = 120, burst: int | None = None, clock=time.time) -> None:
        if per_minute <= 0:
            raise ValueError("per_minute must be positive")
        if burst is not None and burst < 1:
            raise ValueError("burst must be at least 1")
        self.ledger = ledger
        self.rate = per_minute / 60.0
        self.capacity = float(burst if burst is not None else per_minute)
        self.clock = clock

    def check(self, key: str) -> None:
        now = self.clock()
        with self.ledger.tx() as tx:
            wait = tx.take_rate_token(key, now, self.rate, self.capacity)
        if wait > 0.0:
            raise RateLimited(wait)
