from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

from .crypto import iso, utcnow


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


@dataclass
class Principal:
    did: str
    kind: str
    name: str
    jurisdiction: str = "DE"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentCard:
    did: str
    name: str
    operator_did: str
    developer: str
    model: str
    skills: list[str] = field(default_factory=list)
    version: str = "0.1.0"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Constraint:
    currency: str = "EUR"
    max_amount: float | None = None
    max_daily_amount: float | None = None
    counterparties_allow: list[str] = field(default_factory=list)
    counterparties_deny: list[str] = field(default_factory=list)
    require_human_above: float | None = None
    audiences: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Grant:
    id: str
    principal_did: str
    agent_did: str
    organization: str
    purpose: str
    scopes: list[str]
    not_before: str
    not_after: str
    constraints: dict[str, Any]
    status: str = "active"
    issued_at: str = field(default_factory=lambda: iso(utcnow()))

    @classmethod
    def create(cls, principal_did, agent_did, organization, purpose, scopes, not_after, constraints=None, not_before=None):
        nb = not_before or utcnow()
        return cls(
            id=new_id("grant"), principal_did=principal_did, agent_did=agent_did,
            organization=organization, purpose=purpose, scopes=scopes,
            not_before=iso(nb), not_after=iso(not_after),
            constraints=(constraints or Constraint()).to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Intent:
    id: str
    agent_did: str
    grant_id: str
    action: str
    amount: float | None = None
    currency: str = "EUR"
    counterparty: str | None = None
    summary: str = ""
    audience: str = "mandate://local"
    nonce: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: iso(utcnow()))

    @classmethod
    def create(cls, agent_did, grant_id, action, **kwargs):
        return cls(id=new_id("intent"), agent_did=agent_did, grant_id=grant_id, action=action, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    allowed: bool
    reasons: list[str]
    requires_human: bool = False
    grant_id: str | None = None
    intent_id: str | None = None
    decided_at: str = field(default_factory=lambda: iso(utcnow()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Receipt:
    id: str
    intent: dict[str, Any]
    decision: dict[str, Any]
    grant_id: str
    agent_did: str
    principal_did: str
    disclosure: dict[str, Any]
    outcome: str
    created_at: str = field(default_factory=lambda: iso(utcnow()))

    @classmethod
    def create(cls, **kwargs):
        return cls(id=new_id("rcpt"), **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
