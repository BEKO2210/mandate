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

    return 2


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
