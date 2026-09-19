from mandate.ledger import Ledger

def test_nonce_unique(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    with led.tx() as tx:
        assert tx.consume_nonce("mandate://a", "aa" * 8, "r1") is True
        assert tx.consume_nonce("mandate://a", "aa" * 8, "r2") is False

def test_budget_reserve_cap(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    with led.tx() as tx:
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000) is True
        assert tx.reserve("g", "EUR", "2026-09-19", 800, 1000) is False
        assert tx.spent("g", "EUR", "2026-09-19") == 800
