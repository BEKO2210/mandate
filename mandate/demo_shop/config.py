"""The guard configuration for the shop demo, built in code so it cannot drift."""

from __future__ import annotations

import sys
from typing import Any

ALLOWED_VENDORS = ["paper-co.example", "office-depot.example"]


def guard_config(orders: str, store: str = ".mandate-shop", python: str | None = None) -> dict[str, Any]:
    """A buyer that may spend 300 EUR a day at two vendors, asks above 100."""
    return {
        "audience": "mandate://shop",
        "server_name": "mandate_shop",
        "store": store,
        "upstream": {
            "command": python or sys.executable,
            "args": ["-m", "mandate.demo_shop.server", "--orders", orders],
        },
        "tools": {
            "list_products": {"action": "shop.catalog.read"},
            "buy": {
                "action": "shop.order.place",
                "amount_from": "amount",
                "currency_from": "currency",
                "counterparty_from": "vendor",
            },
        },
        "grant": {
            "organization": "Demo Co",
            "purpose": "office supplies",
            "constraints": {
                "currency": "EUR",
                "max_amount": 500,
                "max_daily_amount": 300,
                "require_human_above": 100,
                "counterparties_allow": list(ALLOWED_VENDORS),
            },
        },
    }
