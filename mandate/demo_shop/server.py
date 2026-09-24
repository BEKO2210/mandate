"""The shop as an MCP server on stdio: `python -m mandate.demo_shop.server --orders FILE`.

Uses the same low-level server API as the guard, so the demo exercises
exactly the protocol surface a real upstream would.
"""

from __future__ import annotations

import argparse
from typing import Any

from .shop import Shop

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_products",
        "description": "List what the shop sells, by vendor, with prices.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "buy",
        "description": "Place an order with a vendor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vendor": {"type": "string"},
                "item": {"type": "string"},
                "amount": {"type": "number"},
                "currency": {"type": "string"},
            },
            "required": ["vendor", "item", "amount", "currency"],
        },
    },
]


def make_shop_server(shop: Shop):
    import mcp.types as types
    from mcp.server.lowlevel import Server

    server = Server("demo-shop")
    tools = [types.Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"]) for t in TOOLS]

    async def on_list(ctx, params):
        return types.ListToolsResult(tools=tools)

    async def on_call(ctx, params):
        args = dict(params.arguments or {})
        if params.name == "list_products":
            text, error = shop.list_products(), False
        elif params.name == "buy":
            try:
                text, error = shop.buy(args["vendor"], args["item"], args["amount"], args["currency"]), False
            except KeyError as exc:
                text, error = f"missing argument {exc}", True
            except ValueError as exc:  # not in the catalogue, or not its price
                text, error = str(exc), True
        else:
            text, error = f"unknown tool {params.name!r}", True
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=error)

    server.add_request_handler("tools/list", types.PaginatedRequestParams, on_list)
    server.add_request_handler("tools/call", types.CallToolRequestParams, on_call)
    return server


async def _run(orders: str) -> None:
    from mcp.server.stdio import stdio_server

    server = make_shop_server(Shop(orders))
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    import anyio

    parser = argparse.ArgumentParser(description="The demo shop, as an MCP server on stdio")
    parser.add_argument("--orders", required=True, help="Where placed orders are appended (JSON lines)")
    args = parser.parse_args(argv)
    anyio.run(_run, args.orders)


if __name__ == "__main__":
    main()
