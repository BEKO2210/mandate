"""SQLite transaction ledger for Mandate v0.2.

The ledger owns race-sensitive state only: nonce/approval replay protection,
budget reservations and execution claims. Every mutating operation is expected
to run inside `Ledger.tx()` which uses `BEGIN IMMEDIATE` so competing writers
serialize before they can observe and spend the same remaining budget.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4


class LedgerError(RuntimeError):
    pass


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = FULL")
        con.execute("PRAGMA busy_timeout = 10000")
        return con

    def _init_schema(self) -> None:
        con = self._connect()
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS consumed_nonces (
                    audience TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    receipt_id TEXT,
                    consumed_at TEXT NOT NULL,
                    PRIMARY KEY (audience, nonce)
                );

                CREATE TABLE IF NOT EXISTS budget_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    day TEXT NOT NULL,
                    amount REAL NOT NULL CHECK (amount >= 0),
                    status TEXT NOT NULL CHECK (status IN ('RESERVED','COMMITTED','RELEASED','UNKNOWN')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_budget_scope
                    ON budget_reservations(grant_id, currency, day, status);

                CREATE TABLE IF NOT EXISTS consumed_approvals (
                    approval_id TEXT PRIMARY KEY,
                    intent_id TEXT,
                    receipt_id TEXT,
                    consumed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS execution_claims (
                    execution_id TEXT PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    claimed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
        finally:
            con.close()

    @contextmanager
    def tx(self) -> Iterator["LedgerTx"]:
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            tx = LedgerTx(con)
            yield tx
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


class LedgerTx:
    def __init__(self, con: sqlite3.Connection) -> None:
        self.con = con

    def consume_nonce(self, audience: str, nonce: str, receipt_id: str | None = None) -> bool:
        if not audience or not nonce:
            return False
        try:
            self.con.execute(
                "INSERT INTO consumed_nonces(audience, nonce, receipt_id, consumed_at) VALUES(?,?,?,?)",
                (audience, nonce, receipt_id, _now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def consume_approval(
        self,
        approval_id: str,
        intent_id: str | None = None,
        receipt_id: str | None = None,
    ) -> bool:
        if not approval_id:
            return False
        try:
            self.con.execute(
                "INSERT INTO consumed_approvals(approval_id, intent_id, receipt_id, consumed_at) VALUES(?,?,?,?)",
                (approval_id, intent_id, receipt_id, _now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def spent(self, grant_id: str, currency: str, day: str) -> float:
        row = self.con.execute(
            """
            SELECT COALESCE(SUM(amount), 0.0) AS total
            FROM budget_reservations
            WHERE grant_id=? AND currency=? AND day=?
              AND status IN ('RESERVED','COMMITTED','UNKNOWN')
            """,
            (grant_id, currency, day),
        ).fetchone()
        return float(row["total"] if row else 0.0)

    def reserve(
        self,
        grant_id: str,
        currency: str,
        day: str,
        amount: float,
        cap: float | None,
        reservation_id: str | None = None,
    ) -> bool:
        amount = float(amount)
        if amount < 0:
            raise LedgerError("negative reservation")
        reservation_id = reservation_id or f"resv_{uuid4().hex}"

        existing = self.con.execute(
            "SELECT grant_id, currency, day, amount, status FROM budget_reservations WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        if existing:
            return (
                existing["grant_id"] == grant_id
                and existing["currency"] == currency
                and existing["day"] == day
                and float(existing["amount"]) == amount
                and existing["status"] in {"RESERVED", "COMMITTED", "UNKNOWN"}
            )

        current = self.spent(grant_id, currency, day)
        if cap is not None and current + amount > float(cap) + 1e-9:
            return False

        now = _now()
        try:
            self.con.execute(
                """
                INSERT INTO budget_reservations(
                    reservation_id, grant_id, currency, day, amount, status, created_at, updated_at
                ) VALUES(?,?,?,?,?,'RESERVED',?,?)
                """,
                (reservation_id, grant_id, currency, day, amount, now, now),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def reservation_status(self, reservation_id: str) -> str | None:
        row = self.con.execute(
            "SELECT status FROM budget_reservations WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        return str(row["status"]) if row else None

    def commit_reservation(self, reservation_id: str) -> bool:
        cur = self.con.execute(
            """
            UPDATE budget_reservations
            SET status='COMMITTED', updated_at=?
            WHERE reservation_id=? AND status='RESERVED'
            """,
            (_now(), reservation_id),
        )
        if cur.rowcount == 1:
            return True
        return self.reservation_status(reservation_id) == "COMMITTED"

    def release_reservation(self, reservation_id: str) -> bool:
        cur = self.con.execute(
            """
            UPDATE budget_reservations
            SET status='RELEASED', updated_at=?
            WHERE reservation_id=? AND status='RESERVED'
            """,
            (_now(), reservation_id),
        )
        return cur.rowcount == 1

    def mark_reservation_unknown(self, reservation_id: str) -> bool:
        cur = self.con.execute(
            """
            UPDATE budget_reservations
            SET status='UNKNOWN', updated_at=?
            WHERE reservation_id=? AND status='RESERVED'
            """,
            (_now(), reservation_id),
        )
        if cur.rowcount == 1:
            return True
        return self.reservation_status(reservation_id) == "UNKNOWN"

    def claim_execution(self, execution_id: str, receipt_id: str, idempotency_key: str) -> bool:
        now = _now()
        try:
            self.con.execute(
                """
                INSERT INTO execution_claims(
                    execution_id, receipt_id, state, idempotency_key, claimed_at, updated_at
                ) VALUES(?,?,'EXECUTING',?,?,?)
                """,
                (execution_id, receipt_id, idempotency_key, now, now),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def finish_execution(self, execution_id: str, state: str) -> bool:
        if state not in {"EXECUTED", "EXECUTION_FAILED", "EXECUTION_UNKNOWN"}:
            raise LedgerError(f"invalid execution terminal state: {state}")
        cur = self.con.execute(
            """
            UPDATE execution_claims
            SET state=?, updated_at=?
            WHERE execution_id=? AND state='EXECUTING'
            """,
            (state, _now(), execution_id),
        )
        return cur.rowcount == 1

    def execution_for_receipt(self, receipt_id: str) -> dict | None:
        row = self.con.execute(
            "SELECT execution_id, receipt_id, state, idempotency_key FROM execution_claims WHERE receipt_id=?",
            (receipt_id,),
        ).fetchone()
        return dict(row) if row else None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
