from mandate.ledger import Ledger


def test_release_frees_budget(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with ledger.tx() as tx:
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000, "r1")
        assert tx.release_reservation("r1")
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000, "r2")


def test_unknown_holds_budget(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with ledger.tx() as tx:
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000, "r1")
        assert tx.mark_reservation_unknown("r1")
        assert not tx.reserve("g", "EUR", "2026-09-19", 800, 1000, "r2")


def test_execution_claim_is_single_use(tmp_path):
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with ledger.tx() as tx:
        assert tx.claim_execution("exec_1", "rcpt_1", "idem_1")
        assert not tx.claim_execution("exec_2", "rcpt_1", "idem_2")
        assert not tx.claim_execution("exec_3", "rcpt_2", "idem_1")
        assert tx.finish_execution("exec_1", "EXECUTED")
