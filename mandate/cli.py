from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from .auth import issue_api_key, normalize_scopes
from .crypto import utcnow, verify_object
from .examples_runner import run_belkis_demo
from .ledger import Ledger

DEFAULT_DB = Path(".mandate") / "mandate.sqlite"


def _ledger(path: str | Path) -> Ledger:
    return Ledger(Path(path))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mandate", description="Identity + Permission + Transaction OS for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="Run the Belkis procurement scenario")
    v = sub.add_parser("verify", help="Verify a signed Mandate object")
    v.add_argument("file")

    keys = sub.add_parser("keys", help="Manage gateway API keys")
    keys_sub = keys.add_subparsers(dest="keys_cmd", required=True)

    new = keys_sub.add_parser("new", help="Issue a key. The token is printed once and never stored.")
    new.add_argument("--db", default=str(DEFAULT_DB))
    new.add_argument("--tenant", required=True)
    new.add_argument("--name", required=True)
    new.add_argument(
        "--scopes",
        default="*",
        help="Comma-separated: intents:write, approvals:write, receipts:read, or *",
    )
    new.add_argument("--days", type=int, default=None, help="Expire the key after N days")

    ls = keys_sub.add_parser("list", help="List keys (never their secrets)")
    ls.add_argument("--db", default=str(DEFAULT_DB))
    ls.add_argument("--tenant", default=None)

    off = keys_sub.add_parser("disable", help="Disable a key immediately")
    off.add_argument("--db", default=str(DEFAULT_DB))
    off.add_argument("--id", required=True)

    mcp_cmd = sub.add_parser("mcp", help="Run Mandate in front of an MCP server")
    mcp_sub = mcp_cmd.add_subparsers(dest="mcp_cmd", required=True)
    mcp_init = mcp_sub.add_parser("init", help="Create the principal, agent and grant")
    mcp_init.add_argument("--config", required=True)
    mcp_serve = mcp_sub.add_parser("serve", help="Serve the guard on stdio")
    mcp_serve.add_argument("--config", required=True)

    signer = sub.add_parser("signer", help="Inspect the keys Mandate signs with")
    signer_sub = signer.add_subparsers(dest="signer_cmd", required=True)
    check = signer_sub.add_parser(
        "check", help="Prove a configured signer can sign, before anything depends on it"
    )
    check.add_argument("--config", required=True, help="An MCP guard configuration file")

    args = p.parse_args(argv)

    if args.cmd == "demo":
        run_belkis_demo()
        return 0

    if args.cmd == "verify":
        obj = json.loads(Path(args.file).read_text(encoding="utf-8"))
        ok = verify_object(obj)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1

    if args.cmd == "keys":
        return _keys(args)

    if args.cmd == "mcp":
        return _mcp(args)

    if args.cmd == "signer":
        return _signer(args)

    return 2


def _mcp(args) -> int:
    from .mcp.config import load_config, read_state

    config = load_config(args.config)

    if args.mcp_cmd == "init":
        from .mcp.server import bootstrap, build_engine

        existing = read_state(config)
        if existing:
            print(f"already initialized: grant {existing['grant_id']}")
            return 0
        # No upstream connection is needed to mint the grant, so the executor
        # is never called here.
        engine, _ = build_engine(config, _refuse_call, sorted(config.mapping.rules))
        state = bootstrap(config, engine)
        print(f"principal : {state['principal_did']}")
        print(f"agent     : {state['agent_did']}")
        print(f"grant     : {state['grant_id']}")
        print(f"scopes    : {', '.join(config.scopes())}")
        if config.agent_signer:
            print(f"agent key : {config.agent_signer.get('kind')} — not written here")
        else:
            print(f"agent key : {config.store_path / 'keys' / 'agent.key'} (development key)")
        print(f"keys in   : {config.store_path / 'keys'} (keep them private)")
        return 0

    if args.mcp_cmd == "serve":
        import anyio

        from .mcp.server import serve

        anyio.run(serve, config)
        return 0

    return 2


def _signer(args) -> int:
    """Answer one question: can this configuration actually sign, and as whom?

    Worth its own command because the alternative is finding out during a tool
    call, where the failure reaches a model as a refused action rather than an
    operator as a fixable error.
    """
    from .mcp.config import load_config, read_state
    from .mcp.server import load_agent_signer
    from .signing import SigningError

    config = load_config(args.config)
    state = read_state(config) or {}
    failed = False

    for label, build in (
        ("agent", lambda: load_agent_signer(config)),
        ("enforcer", config.build_enforcer_signer),
    ):
        try:
            signer = build()
        except (SigningError, FileNotFoundError) as exc:
            print(f"{label:<9}: UNUSABLE — {exc}")
            failed = True
            continue
        if signer is None:
            print(f"{label:<9}: local development key in {config.store_path}")
            continue
        try:
            report = signer.check()
        except SigningError as exc:
            print(f"{label:<9}: UNUSABLE — {exc}")
            failed = True
            continue
        held = "held by this process" if report["signer"] == "file" else "held elsewhere"
        print(f"{label:<9}: {report['signer']} ok, {held}")
        print(f"{'':9}  {report['did']}")
        expected = state.get("agent_did") if label == "agent" else None
        if expected and expected != report["did"]:
            print(f"{'':9}  MISMATCH — the grant was issued to {expected}")
            failed = True

    return 1 if failed else 0


async def _refuse_call(name: str, arguments: dict) -> None:
    raise RuntimeError("this engine was built for setup only and cannot dispatch")


def _keys(args) -> int:
    ledger = _ledger(args.db)
    try:
        if args.keys_cmd == "new":
            scopes = normalize_scopes(args.scopes.split(","))
            expires = utcnow() + timedelta(days=args.days) if args.days else None
            token, key_id = issue_api_key(
                ledger, tenant=args.tenant, name=args.name, scopes=scopes, expires_at=expires
            )
            print(f"key id   : {key_id}")
            print(f"tenant   : {args.tenant}")
            print(f"scopes   : {','.join(sorted(scopes))}")
            print(f"expires  : {expires.isoformat() if expires else 'never'}")
            print(f"token    : {token}")
            print("Store the token now. It is not recoverable.")
            return 0

        if args.keys_cmd == "list":
            with ledger.tx() as tx:
                rows = tx.list_api_keys(args.tenant)
            for r in rows:
                state = "disabled" if r["disabled"] else "active"
                print(
                    f"{r['id']}  {r['tenant']:<16} {state:<8} {r['scopes']:<40} "
                    f"{r['name']} (created {r['created_at']}, expires {r['expires_at'] or 'never'})"
                )
            if not rows:
                print("no keys")
            return 0

        if args.keys_cmd == "disable":
            with ledger.tx() as tx:
                changed = tx.disable_api_key(args.id)
                if changed:
                    tx.audit("apikey.disabled", {"key_id": args.id})
            print("disabled" if changed else "no active key with that id")
            return 0 if changed else 1
    finally:
        ledger.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
