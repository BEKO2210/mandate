from __future__ import annotations

from typing import Any

from .crypto import iso, utcnow
from .models import AgentCard, Grant, Intent


def article50(agent: AgentCard, grant: Grant, intent: Intent | None = None) -> dict[str, Any]:
    human = (
        f"Dies ist ein KI-Agent namens «{agent.name}». "
        f"Er handelt im Auftrag von {grant.organization} "
        f"(Mandant: {grant.principal_did}) für den Zweck: {grant.purpose}."
    )
    if intent and intent.summary:
        human += f" Aktuelle Handlung: {intent.summary}."
    return {
        "type": "MandateDisclosure",
        "standard": "eu-ai-act-art-50",
        "version": "2026-08-02",
        "is_ai": True,
        "agent": {
            "did": agent.did,
            "name": agent.name,
            "model": agent.model,
            "operator_did": agent.operator_did,
            "developer": agent.developer,
        },
        "on_behalf_of": {
            "principal_did": grant.principal_did,
            "organization": grant.organization,
            "purpose": grant.purpose,
            "grant_id": grant.id,
            "valid_until": grant.not_after,
        },
        "human_readable": human,
        "machine_readable_mark": "ai-generated-or-acting",
        "issued_at": iso(utcnow()),
    }
