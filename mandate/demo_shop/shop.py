"""The shop itself: a catalogue and an order book. No MCP, no Mandate."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

CATALOG = [
    {"vendor": "paper-co.example", "item": "copy paper, 10 boxes", "price": 40, "currency": "EUR"},
    {"vendor": "paper-co.example", "item": "sticky notes", "price": 20, "currency": "EUR"},
    {"vendor": "office-depot.example", "item": "laptop", "price": 250, "currency": "EUR"},
    {"vendor": "office-depot.example", "item": "office chair", "price": 180, "currency": "EUR"},
    {"vendor": "shady-imports.example", "item": "toner, unbranded", "price": 25, "currency": "EUR"},
]


class Shop:
    def __init__(self, orders_path: str | Path) -> None:
        self.orders_path = Path(orders_path)

    def list_products(self) -> str:
        lines = [f"{p['vendor']:<24} {p['item']:<24} {p['price']:>5} {p['currency']}" for p in CATALOG]
        return "\n".join(lines)

    def buy(self, vendor: str, item: str, amount: float, currency: str) -> str:
        """Place an order at the catalogue price, or refuse it.

        The guard authorizes the amount the agent states. A shop that booked
        whatever it was told would let "a laptop for 1 EUR" slip under the
        approval threshold and ship at 250 — so the price is the catalogue's,
        and a stated amount that differs is refused.
        """
        listed = next((p for p in CATALOG if p["vendor"] == vendor and p["item"] == item), None)
        if listed is None:
            raise ValueError(f"{vendor} does not sell {item!r}")
        if amount != listed["price"] or currency != listed["currency"]:
            raise ValueError(
                f"{item} from {vendor} costs {listed['price']} {listed['currency']}, "
                f"not {amount} {currency}; nothing was ordered"
            )
        order = {
            "order_id": "ord_" + uuid4().hex[:10],
            "vendor": vendor,
            "item": item,
            "amount": amount,
            "currency": currency,
        }
        self.orders_path.parent.mkdir(parents=True, exist_ok=True)
        with self.orders_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(order, sort_keys=True) + "\n")
        return f"Order {order['order_id']} placed: {item} from {vendor}, {amount} {currency}."

    def orders(self) -> list[dict]:
        if not self.orders_path.exists():
            return []
        return [json.loads(line) for line in self.orders_path.read_text(encoding="utf-8").splitlines() if line]
