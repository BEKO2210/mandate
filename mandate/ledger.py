"""SQLite ACID ledger. Separate from KeyProvider."""

from __future__ import annotations

import json
import sqlite3
import threading
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from .chain import body_hash as chain_body_hash
from .chain import loads_strict
from .crypto import iso, utcnow, verify_object
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
              body TEXT NOT NULL,
              tenant TEXT NOT NULL DEFAULT 'default'
            );
            CREATE TABLE IF NOT EXISTS agents (
              did TEXT PRIMARY KEY,
              body TEXT NOT NULL,
              tenant TEXT NOT NULL DEFAULT 'default'
            );
            CREATE TABLE IF NOT EXISTS grants (
              id TEXT PRIMARY KEY,
              principal_did TEXT NOT NULL,
              agent_did TEXT NOT NULL,
              status TEXT NOT NULL,
              body TEXT NOT NULL,
              tenant TEXT NOT NULL DEFAULT 'default'
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
              body TEXT NOT NULL,
              tenant TEXT NOT NULL DEFAULT 'default'
            );
            CREATE TABLE IF NOT EXISTS nonces (
              tenant TEXT NOT NULL DEFAULT 'default',
              audience TEXT NOT NULL,
              nonce TEXT NOT NULL,
              receipt_id TEXT,
              PRIMARY KEY (tenant, audience, nonce)
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
            CREATE TABLE IF NOT EXISTS api_keys (
              id TEXT PRIMARY KEY,
              tenant TEXT NOT NULL,
              name TEXT NOT NULL,
              secret_hash TEXT NOT NULL,
              scopes TEXT NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT,
              disabled INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              event TEXT NOT NULL,
              correlation_id TEXT,
              payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chain (
              tenant TEXT NOT NULL,
              seq INTEGER NOT NULL,
              receipt_id TEXT NOT NULL,
              outcome TEXT NOT NULL,
              body_hash TEXT NOT NULL,
              prev TEXT NOT NULL,
              entry_hash TEXT NOT NULL,
              recorded_at TEXT NOT NULL,
              signer TEXT NOT NULL,
              signature TEXT NOT NULL,
              PRIMARY KEY (tenant, seq)
            );
            -- An entry may appear at exactly one position: without this, an
            -- operator could replay a real, correctly signed entry elsewhere
            -- in the chain.
            CREATE UNIQUE INDEX IF NOT EXISTS chain_entry_hash ON chain(entry_hash);
            CREATE INDEX IF NOT EXISTS chain_receipt ON chain(receipt_id);
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
        if self._schema_version() < 3:
            self._migrate_add_tenancy()
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '3')"
            )
        if self._schema_version() < 4:
            self._migrate_start_chain()

    def _migrate_start_chain(self) -> None:
        """Start the chain, and snapshot the receipts that predate it.

        One transaction, with the version re-checked after the write lock is
        held. Without that, two processes could both see version 3, one could
        finish and write a chained receipt, and the other could then count that
        receipt into the baseline — inflating the very number that bounds how
        many unchained receipts are tolerated.

        The chain starts empty. Seeding it from the receipts that already exist
        would produce a chain that looks like it covered them all along; it did
        not, and a verifier has to be able to say so.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if self._schema_version() >= 4:
                self._conn.execute("ROLLBACK")
                return
            legacy = {
                row["tenant"]: row["n"]
                for row in self._conn.execute(
                    "SELECT tenant, COUNT(*) AS n FROM receipts GROUP BY tenant"
                )
            }
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('chain_started_at', ?)",
                (iso(utcnow()),),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('chain_legacy', ?)",
                (json.dumps(legacy, sort_keys=True),),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '4')"
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def _migrate_add_tenancy(self) -> None:
        """Every record belongs to a tenant. Pre-0.4 rows join the default one."""
        for table in ("principals", "agents", "grants", "receipts"):
            cols = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            if "tenant" not in cols:
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'"
                )
            self._conn.execute(
                f"UPDATE {table} SET tenant='default' WHERE tenant IS NULL OR tenant=''"
            )
        nonce_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(nonces)")}
        if "tenant" not in nonce_cols:
            # The primary key itself has to gain the tenant, otherwise one
            # tenant could burn another tenant's nonces, so the table is rebuilt.
            self._conn.executescript(
                """
                CREATE TABLE nonces_v3 (
                  tenant TEXT NOT NULL,
                  audience TEXT NOT NULL,
                  nonce TEXT NOT NULL,
                  receipt_id TEXT,
                  PRIMARY KEY (tenant, audience, nonce)
                );
                INSERT OR IGNORE INTO nonces_v3(tenant, audience, nonce, receipt_id)
                  SELECT 'default', audience, nonce, receipt_id FROM nonces;
                DROP TABLE nonces;
                ALTER TABLE nonces_v3 RENAME TO nonces;
                """
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

    def put_principal(self, did: str, body: dict, tenant: str = "default") -> None:
        self.l._conn.execute(
            "INSERT OR REPLACE INTO principals(did, body, tenant) VALUES (?,?,?)",
            (did, json.dumps(body), tenant),
        )

    def put_agent(self, did: str, body: dict, tenant: str = "default") -> None:
        self.l._conn.execute(
            "INSERT OR REPLACE INTO agents(did, body, tenant) VALUES (?,?,?)",
            (did, json.dumps(body), tenant),
        )

    def get_agent(self, did: str, tenant: str | None = None) -> dict | None:
        """A DID from another tenant reads as absent, not as forbidden."""
        if tenant is None:
            row = self.l._conn.execute("SELECT body FROM agents WHERE did=?", (did,)).fetchone()
        else:
            row = self.l._conn.execute(
                "SELECT body FROM agents WHERE did=? AND tenant=?", (did, tenant)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def put_grant(
        self, grant_id: str, principal_did: str, agent_did: str, status: str, body: dict,
        tenant: str = "default",
    ) -> None:
        self.l._conn.execute(
            """INSERT OR REPLACE INTO grants(id, principal_did, agent_did, status, body, tenant)
               VALUES (?,?,?,?,?,?)""",
            (grant_id, principal_did, agent_did, status, json.dumps(body), tenant),
        )

    def get_grant(self, grant_id: str, tenant: str | None = None) -> dict | None:
        if tenant is None:
            row = self.l._conn.execute("SELECT body FROM grants WHERE id=?", (grant_id,)).fetchone()
        else:
            row = self.l._conn.execute(
                "SELECT body FROM grants WHERE id=? AND tenant=?", (grant_id, tenant)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def grant_tenant(self, grant_id: str) -> str | None:
        row = self.l._conn.execute("SELECT tenant FROM grants WHERE id=?", (grant_id,)).fetchone()
        return row["tenant"] if row else None

    def consume_nonce(
        self, audience: str, nonce: str, receipt_id: str, tenant: str = "default"
    ) -> bool:
        try:
            self.l._conn.execute(
                "INSERT INTO nonces(tenant, audience, nonce, receipt_id) VALUES (?,?,?,?)",
                (tenant, audience, nonce, receipt_id),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def put_api_key(
        self, key_id: str, tenant: str, name: str, secret_hash: str, scopes: str,
        created_at: str, expires_at: str | None,
    ) -> None:
        self.l._conn.execute(
            """INSERT INTO api_keys(id, tenant, name, secret_hash, scopes, created_at, expires_at, disabled)
               VALUES (?,?,?,?,?,?,?,0)""",
            (key_id, tenant, name, secret_hash, scopes, created_at, expires_at),
        )

    def get_api_key(self, key_id: str) -> dict | None:
        row = self.l._conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
        return dict(row) if row else None

    def disable_api_key(self, key_id: str) -> bool:
        cur = self.l._conn.execute(
            "UPDATE api_keys SET disabled=1 WHERE id=? AND disabled=0", (key_id,)
        )
        return cur.rowcount == 1

    def list_api_keys(self, tenant: str | None = None) -> list[dict]:
        if tenant is None:
            rows = self.l._conn.execute(
                "SELECT id, tenant, name, scopes, created_at, expires_at, disabled FROM api_keys"
            ).fetchall()
        else:
            rows = self.l._conn.execute(
                """SELECT id, tenant, name, scopes, created_at, expires_at, disabled
                   FROM api_keys WHERE tenant=?""",
                (tenant,),
            ).fetchall()
        return [dict(r) for r in rows]

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

    def insert_receipt(self, rec: dict, chain: dict) -> None:
        """A receipt and its first chain entry land together or not at all.

        `chain` is required rather than optional on purpose: an unchained
        receipt is exactly the gap this feature exists to close, and a default
        would let a future caller reopen it by forgetting an argument.
        """
        self.append_chain(chain)
        self.l._conn.execute(
            """INSERT INTO receipts(id, grant_id, agent_did, principal_did, audience, nonce,
               action, amount, amount_minor, currency, state, execution_id, body, budget_day,
               tenant)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec["id"], rec["grant_id"], rec["agent_did"], rec["principal_did"],
                rec["audience"], rec["nonce"], rec["action"], rec.get("amount"),
                rec.get("amount_minor"),
                rec.get("currency"), rec["state"], rec.get("execution_id"),
                json.dumps(rec["body"]), rec.get("budget_day"),
                rec.get("tenant", "default"),
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

    def get_receipt(self, receipt_id: str, tenant: str | None = None) -> dict | None:
        """A receipt of another tenant reads as absent, never as forbidden."""
        if tenant is None:
            row = self.l._conn.execute(
                "SELECT * FROM receipts WHERE id=?", (receipt_id,)
            ).fetchone()
        else:
            row = self.l._conn.execute(
                "SELECT * FROM receipts WHERE id=? AND tenant=?", (receipt_id, tenant)
            ).fetchone()
        if not row:
            return None
        return dict(row)

    def cas_state(
        self, receipt_id: str, src: str, dst: str, body: dict | None = None,
        chain: dict | None = None,
    ) -> bool:
        """Move a receipt's state and record the move in the chain.

        `chain` is keyword-optional only so the signature stays readable; a
        missing one raises. The entry is appended after the CAS succeeds, so a
        lost race leaves no entry for a transition that never happened.
        """
        # Before the transition check: a caller who forgot the chain entry has
        # made a programming error, and should be told that one, whether or not
        # the transition they asked for was also illegal.
        if chain is None:
            raise StorageError("a state change must be chained")
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
        if cur.rowcount != 1:
            return False
        self.append_chain(chain)
        return True

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

    # --- the receipt chain ------------------------------------------------

    def chain_head(self, tenant: str) -> dict | None:
        """The last entry of a tenant's chain, read inside the transaction.

        Reading the head and appending the next entry have to be one atomic
        step or two concurrent writers would both build on the same `prev`.
        `BEGIN IMMEDIATE` makes that so for every caller of `tx()`.
        """
        row = self.l._conn.execute(
            "SELECT * FROM chain WHERE tenant=? ORDER BY seq DESC LIMIT 1", (tenant,)
        ).fetchone()
        return dict(row) if row else None

    def append_chain(self, entry: dict) -> None:
        try:
            self.l._conn.execute(
                """INSERT INTO chain(tenant, seq, receipt_id, outcome, body_hash, prev,
                   entry_hash, recorded_at, signer, signature)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry["tenant"], entry["seq"], entry["receipt_id"], entry["outcome"],
                    entry["body_hash"], entry["prev"], entry["entry_hash"],
                    entry["recorded_at"], entry["signer"], entry["signature"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            # Either seq is taken or this exact entry already sits elsewhere in
            # the chain. Both mean the caller is about to write history that
            # does not follow from what is there.
            raise StorageError(f"chain entry {entry.get('seq')} is not appendable: {exc}") from exc
        except KeyError as exc:
            raise StorageError(f"chain entry is missing {exc}") from exc

    def chain_entries(self, tenant: str) -> list[dict]:
        rows = self.l._conn.execute(
            "SELECT * FROM chain WHERE tenant=? ORDER BY seq ASC", (tenant,)
        ).fetchall()
        return [dict(r) for r in rows]

    def chain_tenants(self) -> list[str]:
        """Every tenant a verifier has to look at — the union, not the chain.

        Taking this from `chain` alone would skip a tenant that has receipts
        and no entries, which is exactly the shape a receipt written around
        the chain has. An operator could open a fresh tenant, insert a forged
        receipt into it, and `mandate chain verify` would report nothing and
        exit 0: the one tenant worth looking at is the one with no chain.
        Review found the omission; it verified as an evasion.
        """
        rows = self.l._conn.execute(
            """SELECT tenant FROM chain
               UNION SELECT tenant FROM receipts
               ORDER BY tenant"""
        ).fetchall()
        return [r["tenant"] for r in rows]

    def receipt_digests(self, tenant: str) -> dict[str, dict[str, Any]]:
        """What the database now says about each receipt, hashed and checked.

        The hash is recomputed from the stored body rather than read from a
        column, so an operator who edits the body cannot also edit a cached
        digest to match.

        Each receipt's own proof is verified here too. The chain proves what
        the set of receipts is; it never asked whether a row in it was ever
        signed. A fabricated receipt in a tenant the chain does not cover
        was sitting unexamined — `verify_object` needs no secret, only the
        DID the proof already names, so there was no reason not to ask.
        """
        out: dict[str, dict[str, Any]] = {}
        for row in self.l._conn.execute(
            "SELECT id, state, body FROM receipts WHERE tenant=?", (tenant,)
        ):
            try:
                body = loads_strict(row["body"])
                digest = {
                    "state": row["state"],
                    "body_hash": chain_body_hash(body),
                    "proof_ok": verify_object(body) if isinstance(body, dict) else False,
                }
            except (ValueError, TypeError) as exc:
                # Reported, not raised: a verifier has to survive bad rows and
                # name them, not stop at the first one. The hashing and the
                # proof check sit inside the boundary rather than after it —
                # an unpaired surrogate raised on the way *out* of parsing and
                # took the entire report with it, findings about other
                # receipts included. One poisoned row must cost one finding,
                # never the run.
                out[row["id"]] = {"state": row["state"], "body_hash": None,
                                  "error": f"stored JSON is unusable ({exc})"}
                continue
            out[row["id"]] = digest
        return out

    def legacy_receipts(self, tenant: str) -> int:
        raw = self.meta("chain_legacy")
        if not raw:
            return 0
        try:
            return int(json.loads(raw).get(tenant, 0))
        except (ValueError, AttributeError, TypeError):
            return 0

    def unchained_receipts(self, tenant: str) -> int:
        """Receipts with no entry at all — the ones that predate the chain."""
        row = self.l._conn.execute(
            """SELECT COUNT(*) AS n FROM receipts r WHERE r.tenant=?
               AND NOT EXISTS (SELECT 1 FROM chain c WHERE c.receipt_id = r.id)""",
            (tenant,),
        ).fetchone()
        return int(row["n"]) if row else 0

    def meta(self, key: str) -> str | None:
        row = self.l._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def audit(self, event: str, payload: dict, correlation_id: str | None = None) -> None:
        safe = {k: v for k, v in payload.items() if k not in {"proof", "private", "token", "authorization", "api_key"}}
        self.l._conn.execute(
            "INSERT INTO audit(ts, event, correlation_id, payload) VALUES (?,?,?,?)",
            (iso(utcnow()), event, correlation_id, json.dumps(safe, default=str)),
        )
