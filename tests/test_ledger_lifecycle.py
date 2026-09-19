"""ChatGPT regression properties, mapped onto the Golden ledger API.

Golden engine talks to reserve/commit_budget/release_budget and unique
execution rows. These tests keep the ChatGPT intent without requiring
reservation_id methods that Golden engine does not call.
"""

import sqlite3

from mandate.ledger import Ledger


def test_release_frees_budget(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with ledger.tx() as tx:
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000)
        assert tx.spent("g", "EUR", "2026-09-19") == 800.0
        tx.release_budget("g", "EUR", "2026-09-19", 800)
        assert tx.spent("g", "EUR", "2026-09-19") == 0.0
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000)
        assert tx.spent("g", "EUR", "2026-09-19") == 800.0


def test_unknown_holds_budget(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with ledger.tx() as tx:
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000)
        # EXECUTION_UNKNOWN keeps the reservation (engine does not release).
        assert not tx.reserve("g", "EUR", "2026-09-19", 800, 1000)
        assert tx.spent("g", "EUR", "2026-09-19") == 800.0


def test_execution_claim_is_single_use(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with ledger.tx() as tx:
        tx.put_execution("exec_1", "rcpt_1", "idem_1", "EXECUTING", {})
        try:
            tx.put_execution("exec_2", "rcpt_1", "idem_2", "EXECUTING", {})
            second_receipt = True
        except sqlite3.IntegrityError:
            second_receipt = False
        try:
            tx.put_execution("exec_3", "rcpt_2", "idem_1", "EXECUTING", {})
            second_idem = True
        except sqlite3.IntegrityError:
            second_idem = False
        assert second_receipt is False
        assert second_idem is False
