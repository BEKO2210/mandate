from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .crypto import KeyPair
from .models import AgentCard, Principal


class Store:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path.cwd() / ".mandate")
        for sub in ("principals", "agents", "keys", "grants", "receipts", "spend"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        self._mem_spend: dict[str, float] = {}

    def _write(self, rel: str, obj: Any) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

    def _read(self, rel: str) -> Any | None:
        path = self.root / rel
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def put_principal(self, p: Principal, kp: KeyPair) -> None:
        self._write(f"principals/{_safe(p.did)}.json", p.to_dict())
        self._write_key(p.did, kp)

    def put_agent(self, card: AgentCard, kp: KeyPair, signed: dict[str, Any]) -> None:
        self._write(f"agents/{_safe(card.did)}.json", signed)
        self._write_key(card.did, kp)

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

    def add_spend(self, grant_id: str, currency: str, amount: float) -> None:
        key = f"{grant_id}:{currency}"
        self._mem_spend[key] = self._mem_spend.get(key, 0.0) + amount
        self._write("spend/ledger.json", self._mem_spend)

    def spent_today(self, grant_id: str, currency: str) -> float:
        saved = self._read("spend/ledger.json") or {}
        self._mem_spend.update({k: float(v) for k, v in saved.items()})
        return float(self._mem_spend.get(f"{grant_id}:{currency}", 0.0))

    def _write_key(self, did: str, kp: KeyPair) -> None:
        self._write(f"keys/{_safe(did)}.json", {"did": did, "private_hex": kp.private_bytes().hex(), "public_hex": kp.public_bytes().hex()})

    def load_key(self, did: str) -> KeyPair:
        doc = self._read(f"keys/{_safe(did)}.json")
        if not doc:
            raise KeyError(did)
        return KeyPair.from_private_bytes(bytes.fromhex(doc["private_hex"]))


def _safe(did: str) -> str:
    return did.replace(":", "_").replace("/", "_")
