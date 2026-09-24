"""`mandate demo shop`: a buyer against the shop, through the guard, over MCP.

No model and no network. The script plays the agent: it starts the guard the
way Claude Code or Cursor would (stdio), calls the shop's tools through it,
and asks a human — here, the CLI with `--yes` — to approve the one purchase
over the threshold. What it prints is what the model would have been told.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import guard_config
from .shop import Shop

STEPS = [
    ("look at the catalogue", "list_products", {}),
    ("copy paper, 40 EUR", "buy", {"vendor": "paper-co.example", "item": "copy paper, 10 boxes", "amount": 40, "currency": "EUR"}),
    ("toner from a vendor the grant does not name", "buy", {"vendor": "shady-imports.example", "item": "toner, unbranded", "amount": 25, "currency": "EUR"}),
    ("an order that names no vendor", "buy", {"item": "sticky notes", "amount": 20, "currency": "EUR"}),
    ("a laptop, 250 EUR — over the approval threshold", "buy", {"vendor": "office-depot.example", "item": "laptop", "amount": 250, "currency": "EUR"}),
    ("a 800 EUR order — over the per-order limit", "buy", {"vendor": "office-depot.example", "item": "office chairs", "amount": 800, "currency": "EUR"}),
    ("APPROVE", None, None),
    ("sticky notes, 20 EUR — the day's budget is spent", "buy", {"vendor": "paper-co.example", "item": "sticky notes", "amount": 20, "currency": "EUR"}),
]

EXPECTED = ["EXECUTED", "EXECUTED", "DENIED", "REFUSED", "HUMAN_REQUIRED", "DENIED", "EXECUTED", "DENIED"]


@dataclass
class Step:
    label: str
    outcome: str
    text: str
    receipt_id: str | None = None


def classify(is_error: bool, text: str) -> str:
    """What the guard's answer means, read the way a model would read it."""
    if not is_error:
        return "EXECUTED"
    if text.startswith("Mandate denied"):
        return "DENIED"
    if text.startswith("Mandate is holding this call"):
        return "HUMAN_REQUIRED"
    if text.startswith("Mandate refused"):
        return "REFUSED"
    return "ERROR"


def _receipt(text: str) -> str | None:
    found = re.search(r"Receipt (rcpt_[0-9a-f]+)", text)
    return found.group(1) if found else None


async def _drive(config_path: Path, approve, errlog) -> list[Step]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from ..mcp.executor import normalize_result

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "mandate", "mcp", "serve", "--config", str(config_path)]
    )
    steps: list[Step] = []
    held: str | None = None
    async with stdio_client(params, errlog=errlog) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for label, tool, args in STEPS:
                if tool is None:
                    ok, text = approve(held)
                    steps.append(Step(f"the human approves {held}", "EXECUTED" if ok else "REFUSED", text, held))
                    continue
                is_error, text = normalize_result(await session.call_tool(tool, args))
                outcome = classify(is_error, text)
                step = Step(label, outcome, text, _receipt(text))
                if outcome == "HUMAN_REQUIRED":
                    held = step.receipt_id
                steps.append(step)
    return steps


def _approve_with_cli(config_path: Path):
    def approve(receipt_id: str | None) -> tuple[bool, str]:
        if receipt_id is None:
            return False, "nothing was held"
        done = subprocess.run(
            [sys.executable, "-m", "mandate", "mcp", "approve", "--config", str(config_path),
             "--receipt", receipt_id, "--yes"],
            capture_output=True, text=True, timeout=120,
        )
        last = (done.stdout.strip().splitlines() or [done.stderr.strip()])[-1]
        return done.returncode == 0, last
    return approve


def run(directory: str | Path | None = None, quiet: bool = False) -> dict:
    """Play the scenario; return what happened, for the CLI and the gates."""
    import anyio

    from ..mcp.config import load_config
    from ..mcp.server import build_engine

    base = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="mandate-shop-"))
    # A second run in the same place would inherit the first one's orders and,
    # the same day, its spent budget — and then not play as documented.
    leftovers = [n for n in ("guard.json", "orders.jsonl", "store") if (base / n).exists()]
    if leftovers:
        raise ValueError(
            f"{base} already holds a demo run ({', '.join(leftovers)}); "
            f"pick an empty directory, or leave out --dir for a fresh one"
        )
    base.mkdir(parents=True, exist_ok=True)
    orders = base / "orders.jsonl"
    config_path = base / "guard.json"
    config_path.write_text(json.dumps(guard_config(str(orders), store="store"), indent=2), encoding="utf-8")

    # The guard's own log goes to a file beside the store, not over the story.
    with (base / "guard.log").open("w", encoding="utf-8") as errlog:
        steps = anyio.run(_drive, config_path, _approve_with_cli(config_path), errlog)

    config = load_config(config_path)
    engine, _ = build_engine(config, _never, sorted(config.mapping.rules))
    report = engine.verify_chain(expect_signer=engine.enforcer_did)
    placed = Shop(orders).orders()
    result = {
        "dir": str(base),
        "outcomes": [s.outcome for s in steps],
        "orders": placed,
        "chain_ok": report.ok,
        "chain_length": getattr(report, "length", None),
    }
    if not quiet:
        _print(steps, result)
    return result


def _never(*_):  # pragma: no cover - the verifying engine never dispatches
    raise RuntimeError("not connected")


def _print(steps: list[Step], result: dict) -> None:
    marks = {"EXECUTED": "RAN    ", "DENIED": "DENIED ", "REFUSED": "REFUSED", "HUMAN_REQUIRED": "HELD   "}
    print("Mandate — an agent buys office supplies, through the MCP guard")
    print("Grant: 300 EUR a day, at most 500 per order, two named vendors, a human above 100.\n")
    for i, step in enumerate(steps, 1):
        first = step.text.splitlines()[0] if step.text else ""
        print(f"{i}. [{marks.get(step.outcome, step.outcome)}] {step.label}")
        print(f"   {first[:150]}")
    total = sum(o["amount"] for o in result["orders"])
    print(f"\nOrders placed: {len(result['orders'])} ({total} EUR). "
          f"Receipt chain: {'intact' if result['chain_ok'] else 'BROKEN'}.")
    print(f"Everything is in {result['dir']} — `mandate chain verify --db {result['dir']}/store/mandate.sqlite`")
