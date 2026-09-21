"""File-backed store. Private keys are never written to disk."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AgentCard, Principal


class Store:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path.cwd() / ".mandate")
        for sub in ("principals", "agents", "grants", "receipts", "spend", "nonces"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    def _write(self, rel: str, obj: Any) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

    def _read(self, rel: str) -> Any | None:
        path = self.root / rel
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def put_principal(self, p: Principal) -> None:
        self._write(f"principals/{_safe(p.did)}.json", p.to_dict())

    def put_agent(self, card: AgentCard, signed: dict[str, Any]) -> None:
        self._write(f"agents/{_safe(card.did)}.json", signed)

    def get_agent(self, did: str) -> AgentCard | None:
        doc = self._read(f"agents/{_safe(did)}.json")
        if not doc:
            return None
        body = {k: v for k, v in doc.items() if k != "proof"}
        return AgentCard(
            did=body["did"], name=body["name"], operator_did=body["operator_did"],
            developer=body["developer"], model=body["model"],
            skills=body.get("skills") or [], version=body.get("version", "0.1.0"),
            extra=body.get("extra") or {},
        )

    def put_grant(self, signed: dict[str, Any]) -> None:
        self._write(f"grants/{signed['id']}.json", signed)

    def get_grant(self, grant_id: str) -> dict[str, Any] | None:
        return self._read(f"grants/{grant_id}.json")

    def put_receipt(self, signed: dict[str, Any]) -> None:
        self._write(f"receipts/{signed['id']}.json", signed)

    def get_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        return self._read(f"receipts/{receipt_id}.json")

    # Spend accounting lives in the SQLite ledger in integer minor units.
    # The float-based helpers that used to sit here were removed in 0.2.2 so
    # no second, inexact money path can come back.

    def consume_nonce(self, nonce: str, audience: str) -> bool:
        if not nonce:
            return False
        key = f"{audience}:{nonce}"
        path = f"nonces/{_safe(key)}.json"
        if self._read(path):
            return False
        self._write(path, {"nonce": nonce, "audience": audience, "used_at": _today()})
        return True


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _safe(did: str) -> str:
    return did.replace(":", "_").replace("/", "_")
