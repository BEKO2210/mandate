"""SQLite ACID ledger. Separate from KeyProvider."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .crypto import iso, utcnow
from .states import InvalidTransition, assert_transition


class StorageError(Exception):
    pass


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._fail = False
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init()

    def inject_failure(self, on: bool = True) -> None:
        self._fail = on

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS principals (
              did TEXT PRIMARY KEY,
              body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
              did TEXT PRIMARY KEY,
              body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants (
              id TEXT PRIMARY KEY,
              principal_did TEXT NOT NULL,
              agent_did TEXT NOT NULL,
              status TEXT NOT NULL,
              body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
              id TEXT PRIMARY KEY,
              grant_id TEXT NOT NULL,
              agent_did TEXT NOT NULL,
              principal_did TEXT NOT NULL,
              audience TEXT NOT NULL,
              nonce TEXT NOT NULL,
              action TEXT NOT NULL,
              amount REAL,
              currency TEXT,
              state TEXT NOT NULL,
              execution_id TEXT,
              body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nonces (
              audience TEXT NOT NULL,
              nonce TEXT NOT NULL,
              receipt_id TEXT,
              PRIMARY KEY (audience, nonce)
            );
            CREATE TABLE IF NOT EXISTS approvals (
              id TEXT PRIMARY KEY,
              receipt_id TEXT NOT NULL,
              nonce TEXT NOT NULL UNIQUE,
              consumed INTEGER NOT NULL DEFAULT 0,
              body TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS approvals_receipt ON approvals(receipt_id);
            CREATE TABLE IF NOT EXISTS budget (
              grant_id TEXT NOT NULL,
              currency TEXT NOT NULL,
              day TEXT NOT NULL,
              reserved REAL NOT NULL DEFAULT 0,
              committed REAL NOT NULL DEFAULT 0,
              PRIMARY KEY (grant_id, currency, day)
            );
            CREATE TABLE IF NOT EXISTS executions (
              id TEXT PRIMARY KEY,
              receipt_id TEXT NOT NULL UNIQUE,
              idempotency_key TEXT NOT NULL UNIQUE,
              state TEXT NOT NULL,
              body TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              event TEXT NOT NULL,
              correlation_id TEXT,
              payload TEXT NOT NULL
            );
            """
        )

    def _check(self) -> None:
        if self._fail:
            raise StorageError("injected storage failure")

    def tx(self):
        return _Tx(self)


class _Tx:
    def __init__(self, ledger: Ledger) -> None:
        self.l = ledger

    def __enter__(self):
        self.l._lock.acquire()
        self.l._check()
        self.l._conn.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.l._conn.execute("COMMIT")
            else:
                self.l._conn.execute("ROLLBACK")
        finally:
            self.l._lock.release()
        return False

    def put_principal(self, did: str, body: dict) -> None:
        self.l._conn.execute(
            "INSERT OR REPLACE INTO principals(did, body) VALUES (?,?)",
            (did, json.dumps(body)),
        )

    def put_agent(self, did: str, body: dict) -> None:
        self.l._conn.execute(
            "INSERT OR REPLACE INTO agents(did, body) VALUES (?,?)",
            (did, json.dumps(body)),
        )

    def get_agent(self, did: str) -> dict | None:
        row = self.l._conn.execute("SELECT body FROM agents WHERE did=?", (did,)).fetchone()
        return json.loads(row["body"]) if row else None

    def put_grant(self, grant_id: str, principal_did: str, agent_did: str, status: str, body: dict) -> None:
        self.l._conn.execute(
            "INSERT OR REPLACE INTO grants(id, principal_did, agent_did, status, body) VALUES (?,?,?,?,?)",
            (grant_id, principal_did, agent_did, status, json.dumps(body)),
        )

    def get_grant(self, grant_id: str) -> dict | None:
        row = self.l._conn.execute("SELECT body FROM grants WHERE id=?", (grant_id,)).fetchone()
        return json.loads(row["body"]) if row else None

    def consume_nonce(self, audience: str, nonce: str, receipt_id: str) -> bool:
        try:
            self.l._conn.execute(
                "INSERT INTO nonces(audience, nonce, receipt_id) VALUES (?,?,?)",
                (audience, nonce, receipt_id),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def spent(self, grant_id: str, currency: str, day: str) -> float:
        row = self.l._conn.execute(
            "SELECT reserved, committed FROM budget WHERE grant_id=? AND currency=? AND day=?",
            (grant_id, currency, day),
        ).fetchone()
        if not row:
            return 0.0
        return float(row["reserved"]) + float(row["committed"])

    def reserve(self, grant_id: str, currency: str, day: str, amount: float, cap: float | None) -> bool:
        if amount is None or amount <= 0:
            return True
        cur = self.spent(grant_id, currency, day)
        if cap is not None and cur + amount > cap:
            return False
        self.l._conn.execute(
            """INSERT INTO budget(grant_id, currency, day, reserved, committed)
               VALUES (?,?,?,?,0)
               ON CONFLICT(grant_id, currency, day)
               DO UPDATE SET reserved = reserved + excluded.reserved""",
            (grant_id, currency, day, amount),
        )
        return True

    def commit_budget(self, grant_id: str, currency: str, day: str, amount: float) -> None:
        if not amount:
            return
        self.l._conn.execute(
            """UPDATE budget SET reserved = reserved - ?, committed = committed + ?
               WHERE grant_id=? AND currency=? AND day=?""",
            (amount, amount, grant_id, currency, day),
        )

    def release_budget(self, grant_id: str, currency: str, day: str, amount: float) -> None:
        if not amount:
            return
        self.l._conn.execute(
            """UPDATE budget SET reserved = MAX(reserved - ?, 0)
               WHERE grant_id=? AND currency=? AND day=?""",
            (amount, grant_id, currency, day),
        )

    def insert_receipt(self, rec: dict) -> None:
        self.l._conn.execute(
            """INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce,
               action, amount, currency, state, execution_id, body)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec["id"], rec["grant_id"], rec["agent_did"], rec["principal_did"],
                rec["audience"], rec["nonce"], rec["action"], rec.get("amount"),
                rec.get("currency"), rec["state"], rec.get("execution_id"),
                json.dumps(rec["body"]),
            ),
        )

    def get_receipt(self, receipt_id: str) -> dict | None:
        row = self.l._conn.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
        if not row:
            return None
        return dict(row)

    def cas_state(self, receipt_id: str, src: str, dst: str, body: dict | None = None) -> bool:
        assert_transition(src, dst)
        if body is None:
            cur = self.l._conn.execute(
                "UPDATE receipts SET state=? WHERE id=? AND state=?",
                (dst, receipt_id, src),
            )
        else:
            cur = self.l._conn.execute(
                "UPDATE receipts SET state=?, body=? WHERE id=? AND state=?",
                (dst, json.dumps(body), receipt_id, src),
            )
        return cur.rowcount == 1

    def set_execution(self, receipt_id: str, execution_id: str) -> None:
        self.l._conn.execute(
            "UPDATE receipts SET execution_id=? WHERE id=?",
            (execution_id, receipt_id),
        )

    def put_approval(self, approval_id: str, receipt_id: str, nonce: str, body: dict) -> bool:
        try:
            self.l._conn.execute(
                "INSERT INTO approvals(id, receipt_id, nonce, consumed, body) VALUES (?,?,?,0,?)",
                (approval_id, receipt_id, nonce, json.dumps(body)),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def consume_approval(self, approval_id: str) -> bool:
        cur = self.l._conn.execute(
            "UPDATE approvals SET consumed=1 WHERE id=? AND consumed=0",
            (approval_id,),
        )
        return cur.rowcount == 1

    def get_approval_by_receipt(self, receipt_id: str) -> dict | None:
        row = self.l._conn.execute(
            "SELECT * FROM approvals WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        return dict(row) if row else None

    def put_execution(self, execution_id: str, receipt_id: str, idem: str, state: str, body: dict | None) -> None:
        prior_r = self.get_execution_by_receipt(receipt_id)
        if prior_r and prior_r["id"] != execution_id:
            raise sqlite3.IntegrityError("receipt already claimed")
        prior_i = self.get_execution_by_idem(idem)
        if prior_i and prior_i["id"] != execution_id:
            raise sqlite3.IntegrityError("idempotency key reused")
        self.l._conn.execute(
            """INSERT INTO executions(id, receipt_id, idempotency_key, state, body)
               VALUES (?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 state=excluded.state,
                 body=excluded.body
               WHERE executions.receipt_id=excluded.receipt_id
                 AND executions.idempotency_key=excluded.idempotency_key""",
            (execution_id, receipt_id, idem, state, json.dumps(body) if body else None),
        )

    def get_execution_by_receipt(self, receipt_id: str) -> dict | None:
        row = self.l._conn.execute(
            "SELECT * FROM executions WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_execution_by_idem(self, idem: str) -> dict | None:
        row = self.l._conn.execute(
            "SELECT * FROM executions WHERE idempotency_key=?", (idem,)
        ).fetchone()
        return dict(row) if row else None

    def audit(self, event: str, payload: dict, correlation_id: str | None = None) -> None:
        safe = {k: v for k, v in payload.items() if k not in {"proof", "private", "token", "authorization", "api_key"}}
        self.l._conn.execute(
            "INSERT INTO audit(ts, event, correlation_id, payload) VALUES (?,?,?,?)",
            (iso(utcnow()), event, correlation_id, json.dumps(safe, default=str)),
        )
