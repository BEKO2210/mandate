"""Demo-shop gates G262-G264.

The demo is what a developer sees first, so it is held to the same standard
as the code it shows: every step has an expected outcome, the budget adds
up, the chain verifies, and the example configuration cannot drift from the
one `mandate mcp init --example shop` writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mandate.demo_shop.config import guard_config
from mandate.demo_shop.scenario import EXPECTED, STEPS, classify
from mandate.demo_shop.shop import Shop
from mandate.mcp.config import parse_config
from mandate.mcp.guard import McpGuard
from mandate.mcp.server import bootstrap, build_engine, load_agent_signer, load_principal_signer

from .test_mcp_gates import _direct_bridge


class ShopUpstream:
    """The shop as the guard's upstream, without a transport."""

    def __init__(self, shop: Shop) -> None:
        self.shop = shop
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "list_products":
            text = self.shop.list_products()
        else:
            try:
                text = self.shop.buy(arguments["vendor"], arguments["item"], arguments["amount"], arguments["currency"])
            except ValueError as exc:
                return {"is_error": True, "content": [{"type": "text", "text": str(exc)}]}
        return {"is_error": False, "content": [{"type": "text", "text": text}]}


def test_g262_the_shop_scenario_decides_as_documented(tmp_path):
    shop = Shop(tmp_path / "orders.jsonl")
    upstream = ShopUpstream(shop)
    config = parse_config(guard_config(str(tmp_path / "orders.jsonl"), store=str(tmp_path / "store")))
    engine, executor = build_engine(config, upstream.call_tool, sorted(config.mapping.rules))
    executor._bridge = _direct_bridge
    state = bootstrap(config, engine)
    guard = McpGuard(
        engine=engine, agent_signer=load_agent_signer(config), grant_id=state["grant_id"],
        mapping=config.mapping, tenant=config.tenant, executor=executor,
    )

    outcomes, held = [], None
    for _, tool, args in STEPS:
        decision = guard.approve(held, load_principal_signer(config)) if tool is None else guard.call(tool, args)
        outcome = classify(not decision.allowed, decision.text)
        if outcome == "HUMAN_REQUIRED":
            held = decision.receipt_id
        outcomes.append(outcome)

    assert outcomes == EXPECTED
    placed = shop.orders()
    assert [(o["vendor"], o["amount"]) for o in placed] == [
        ("paper-co.example", 40), ("office-depot.example", 250),
    ]
    assert sum(o["amount"] for o in placed) <= 300, "the daily cap held"
    # The refused, denied and held calls never reached the shop.
    assert [name for name, _ in upstream.calls] == ["list_products", "buy", "buy"]
    assert engine.verify_chain(expect_signer=engine.enforcer_did).ok

    # Understating the price does not walk around the threshold: the guard
    # authorizes the 1 EUR it is told, and the shop refuses to sell at it.
    understated = guard.call(
        "buy", {"vendor": "office-depot.example", "item": "laptop", "amount": 1, "currency": "EUR"},
    )
    assert not understated.allowed and understated.outcome == "EXECUTION_FAILED"
    assert "costs 250 EUR" in understated.text
    assert len(shop.orders()) == 2, "nothing is booked at a price the shop does not charge"


def test_g263_the_demo_runs_end_to_end_over_stdio(tmp_path):
    """The real thing: the guard as a subprocess an MCP client starts, the
    shop as its upstream, and the approval through `mandate mcp approve`."""
    pytest.importorskip("mcp", reason="the demo runs the guard over MCP")
    from mandate.demo_shop.scenario import run

    result = run(tmp_path, quiet=True)

    assert result["outcomes"] == EXPECTED
    assert len(result["orders"]) == 2
    assert result["chain_ok"]
    assert "UNMAPPED" in (tmp_path / "guard.log").read_text(encoding="utf-8")

    # A second run in the same place would inherit today's spent budget.
    with pytest.raises(ValueError, match="already holds a demo run"):
        run(tmp_path, quiet=True)
    assert len(Shop(tmp_path / "orders.jsonl").orders()) == 2


def test_g264_the_example_configuration_is_the_one_init_writes():
    example = json.loads(Path("examples/mcp_shop/guard.json").read_text(encoding="utf-8"))
    written = guard_config("orders.jsonl", store=".mandate-shop")
    for key in ("audience", "server_name", "tools", "grant", "store"):
        assert example[key] == written[key], key
    assert example["upstream"]["args"] == written["upstream"]["args"]
    parse_config(example)  # and it is a configuration the guard accepts
