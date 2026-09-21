"""SQLite ACID ledger. Separate from KeyProvider."""

from __future__ import annotations

import json
import sqlite3
import threading
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from .crypto import iso, utcnow
from .money import exponent, from_minor
from .states import InvalidTransition, assert_transition


class StorageError(Exception):
    pass


def _require_int(value: Any, what: str) -> int:
    """Money reaches the ledger as integer minor units or not at all."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise StorageError(f"{what} must be integer minor units, got {value!r}")
    return value


def _legacy_minor(value: Any, currency: str) -> int:
    if value is None:
        return 0
    scaled = Decimal(str(value)).scaleb(exponent(currency or "EUR"))
    return int(scaled.quantize(Decimal(1), rounding=ROUND_HALF_UP))


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
        self._migrate()

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
              reserved INTEGER NOT NULL DEFAULT 0,
              committed INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (grant_id, currency, day)
            );
            CREATE TABLE IF NOT EXISTS executions (
              id TEXT PRIMARY KEY,
              receipt_id TEXT NOT NULL UNIQUE,
              idempotency_key TEXT NOT NULL UNIQUE,
              state TEXT NOT NULL,
              started_at TEXT,
              body TEXT
            );
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
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

    def _migrate(self) -> None:
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(receipts)")}
        if "budget_day" not in cols:
            self._conn.execute("ALTER TABLE receipts ADD COLUMN budget_day TEXT")
        if "amount_minor" not in cols:
            self._conn.execute("ALTER TABLE receipts ADD COLUMN amount_minor INTEGER")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS budget_bindings (
              receipt_id TEXT PRIMARY KEY,
              grant_id TEXT NOT NULL,
              currency TEXT NOT NULL,
              day TEXT NOT NULL,
              amount REAL NOT NULL
            );
            """
        )
        binding_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(budget_bindings)")}
        if "amount_minor" not in binding_cols:
            self._conn.execute("ALTER TABLE budget_bindings ADD COLUMN amount_minor INTEGER")
        exec_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(executions)")}
        if "started_at" not in exec_cols:
            self._conn.execute("ALTER TABLE executions ADD COLUMN started_at TEXT")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        if self._schema_version() < 2:
            self._migrate_amounts_to_minor()
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '2')"
            )

    def _schema_version(self) -> int:
        row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        try:
            return int(row["value"]) if row else 0
        except (TypeError, ValueError):
            return 0

    def _migrate_amounts_to_minor(self) -> None:
        """Convert pre-0.2.2 float amounts to integer minor units.

        Legacy rows can hold values a float never represented exactly (0.30 is
        stored as 0.29999999999999998). Nothing can recover the intended value
        from them, so migration rounds half-up to the nearest minor unit once,
        here, and every later decision is exact.
        """
        for row in self._conn.execute(
            "SELECT grant_id, currency, day, reserved, committed FROM budget"
        ).fetchall():
            self._conn.execute(
                "UPDATE budget SET reserved=?, committed=? WHERE grant_id=? AND currency=? AND day=?",
                (
                    _legacy_minor(row["reserved"], row["currency"]),
                    _legacy_minor(row["committed"], row["currency"]),
                    row["grant_id"],
                    row["currency"],
                    row["day"],
                ),
            )
        for row in self._conn.execute(
            "SELECT receipt_id, currency, amount FROM budget_bindings"
        ).fetchall():
            self._conn.execute(
                "UPDATE budget_bindings SET amount_minor=? WHERE receipt_id=?",
                (_legacy_minor(row["amount"], row["currency"]), row["receipt_id"]),
            )
        for row in self._conn.execute(
            "SELECT id, currency, amount FROM receipts WHERE amount IS NOT NULL"
        ).fetchall():
            self._conn.execute(
                "UPDATE receipts SET amount_minor=? WHERE id=?",
                (_legacy_minor(row["amount"], row["currency"] or "EUR"), row["id"]),
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

    def spent(self, grant_id: str, currency: str, day: str) -> int:
        """Reserved plus committed minor units for this grant/currency/day."""
        row = self.l._conn.execute(
            "SELECT reserved, committed FROM budget WHERE grant_id=? AND currency=? AND day=?",
            (grant_id, currency, day),
        ).fetchone()
        if not row:
            return 0
        return int(row["reserved"]) + int(row["committed"])

    def reserve(self, grant_id: str, currency: str, day: str, amount: int, cap: int | None) -> bool:
        """Reserve integer minor units against an integer minor-unit cap."""
        if amount is None or amount <= 0:
            return True
        amount = _require_int(amount, "reserve amount")
        cur = self.spent(grant_id, currency, day)
        if cap is not None and cur + amount > _require_int(cap, "cap"):
            return False
        self.l._conn.execute(
            """INSERT INTO budget(grant_id, currency, day, reserved, committed)
               VALUES (?,?,?,?,0)
               ON CONFLICT(grant_id, currency, day)
               DO UPDATE SET reserved = reserved + excluded.reserved""",
            (grant_id, currency, day, amount),
        )
        return True

    def commit_budget(self, grant_id: str, currency: str, day: str, amount: int) -> None:
        if not amount:
            return
        amount = _require_int(amount, "commit amount")
        self.l._conn.execute(
            """UPDATE budget SET reserved = MAX(reserved - ?, 0), committed = committed + ?
               WHERE grant_id=? AND currency=? AND day=?""",
            (amount, amount, grant_id, currency, day),
        )

    def release_budget(self, grant_id: str, currency: str, day: str, amount: int) -> None:
        if not amount:
            return
        amount = _require_int(amount, "release amount")
        self.l._conn.execute(
            """UPDATE budget SET reserved = MAX(reserved - ?, 0)
               WHERE grant_id=? AND currency=? AND day=?""",
            (amount, grant_id, currency, day),
        )

    def insert_receipt(self, rec: dict) -> None:
        self.l._conn.execute(
            """INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce,
               action, amount, amount_minor, currency, state, execution_id, body, budget_day)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec["id"], rec["grant_id"], rec["agent_did"], rec["principal_did"],
                rec["audience"], rec["nonce"], rec["action"], rec.get("amount"),
                rec.get("amount_minor"),
                rec.get("currency"), rec["state"], rec.get("execution_id"),
                json.dumps(rec["body"]), rec.get("budget_day"),
            ),
        )

    def put_budget_binding(
        self, receipt_id: str, grant_id: str, currency: str, day: str, amount_minor: int
    ) -> None:
        amount_minor = _require_int(amount_minor or 0, "binding amount")
        self.l._conn.execute(
            """INSERT OR REPLACE INTO budget_bindings
               (receipt_id, grant_id, currency, day, amount, amount_minor)
               VALUES (?,?,?,?,?,?)""",
            (
                receipt_id, grant_id, currency, day,
                float(from_minor(amount_minor, currency)), amount_minor,
            ),
        )

    def get_budget_binding(self, receipt_id: str) -> dict | None:
        row = self.l._conn.execute(
            "SELECT * FROM budget_bindings WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if not row:
            return None
        binding = dict(row)
        if binding.get("amount_minor") is None:
            # Pre-0.2.2 binding without an exact amount must not be trusted.
            return None
        binding["amount_minor"] = int(binding["amount_minor"])
        return binding

    def budget_snapshot(self, grant_id: str, currency: str, day: str) -> dict[str, Decimal]:
        """Major-unit view for reporting. Decimal, so comparisons stay exact."""
        snap = self.budget_snapshot_minor(grant_id, currency, day)
        return {
            "reserved": from_minor(snap["reserved"], currency),
            "committed": from_minor(snap["committed"], currency),
        }

    def budget_snapshot_minor(self, grant_id: str, currency: str, day: str) -> dict[str, int]:
        row = self.l._conn.execute(
            "SELECT reserved, committed FROM budget WHERE grant_id=? AND currency=? AND day=?",
            (grant_id, currency, day),
        ).fetchone()
        if not row:
            return {"reserved": 0, "committed": 0}
        return {"reserved": int(row["reserved"]), "committed": int(row["committed"])}

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

    def set_receipt_budget_day(self, receipt_id: str, day: str) -> None:
        self.l._conn.execute("UPDATE receipts SET budget_day=? WHERE id=?", (day, receipt_id))

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

    def put_execution(
        self,
        execution_id: str,
        receipt_id: str,
        idem: str,
        state: str,
        body: dict | None,
        started_at: str | None = None,
    ) -> None:
        prior_r = self.get_execution_by_receipt(receipt_id)
        if prior_r and prior_r["id"] != execution_id:
            raise sqlite3.IntegrityError("receipt already claimed")
        prior_i = self.get_execution_by_idem(idem)
        if prior_i and prior_i["id"] != execution_id:
            raise sqlite3.IntegrityError("idempotency key reused")
        self.l._conn.execute(
            """INSERT INTO executions(id, receipt_id, idempotency_key, state, started_at, body)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 state=excluded.state,
                 body=excluded.body
               WHERE executions.receipt_id=excluded.receipt_id
                 AND executions.idempotency_key=excluded.idempotency_key""",
            (
                execution_id, receipt_id, idem, state,
                started_at or iso(utcnow()),
                json.dumps(body) if body else None,
            ),
        )

    def stale_executions(self, cutoff_iso: str) -> list[dict]:
        """Executions still claimed as EXECUTING that started before the cutoff."""
        rows = self.l._conn.execute(
            """SELECT e.id AS execution_id, e.receipt_id, e.started_at, r.state
               FROM executions e JOIN receipts r ON r.id = e.receipt_id
               WHERE r.state = 'EXECUTING'
                 AND (e.started_at IS NULL OR e.started_at < ?)""",
            (cutoff_iso,),
        ).fetchall()
        return [dict(row) for row in rows]

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
