import threading
from mandate.ledger import Ledger

def test_parallel_reserve(tmp_path):
    led = Ledger(tmp_path / "c.sqlite")
    wins = []
    def go():
        with led.tx() as tx:
            wins.append(tx.reserve("g", "EUR", "2026-09-19", 800, 1000))
    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert sum(1 for w in wins if w) == 1
