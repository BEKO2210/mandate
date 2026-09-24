# An agent that buys office supplies

A small shop served over MCP (`mandate.demo_shop`), with the Mandate guard in
front of it. The grant in [`guard.json`](guard.json):

| Limit | Value |
|---|---|
| Per order | at most 500 EUR |
| Per day | at most 300 EUR |
| Vendors | `paper-co.example`, `office-depot.example` — nobody else |
| Human approval | every order above 100 EUR |

## Watch it, no model needed

```bash
pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"
mandate demo shop
```

```
1. [RAN    ] look at the catalogue
2. [RAN    ] copy paper, 40 EUR
3. [DENIED ] toner from a vendor the grant does not name
4. [REFUSED] an order that names no vendor
5. [HELD   ] a laptop, 250 EUR — over the approval threshold
6. [DENIED ] a 800 EUR order — over the per-order limit
7. [RAN    ] the human approves rcpt_…
8. [DENIED ] sticky notes, 20 EUR — the day's budget is spent

Orders placed: 2 (290 EUR). Receipt chain: intact.
```

The script starts the guard over stdio exactly as an MCP client does, and
approves step 5 with `mandate mcp approve` while the guard is running.

The shop books only at catalogue prices. The guard authorizes the amount the
agent states, so a shop that accepted "a laptop for 1 EUR" would let an order
slip under the approval threshold; this one refuses it, and nothing is ordered.

## Try it with Claude Code or Cursor

```bash
mkdir shop && cd shop
mandate mcp init --config guard.json --example shop
```

`init` writes this configuration with absolute paths, creates the grant, and
prints the `claude mcp add …` line and the `mcpServers` entry to paste. Then
ask the agent to buy a laptop for 250 EUR from office-depot.example, and
approve it yourself:

```bash
mandate mcp pending --config guard.json
mandate mcp approve --config guard.json --receipt rcpt_…
```

The `guard.json` in this directory is the same configuration with portable
paths (`python3`, relative `orders.jsonl`), for reading; a gate keeps its
tools and grant identical to what `--example shop` writes.
