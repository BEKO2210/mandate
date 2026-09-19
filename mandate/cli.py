from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .crypto import verify_object
from .examples_runner import run_belkis_demo


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mandate", description="Identity + Permission + Transaction OS for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="Run the Belkis procurement scenario")
    v = sub.add_parser("verify", help="Verify a signed Mandate object")
    v.add_argument("file")
    args = p.parse_args(argv)
    if args.cmd == "demo":
        run_belkis_demo()
        return 0
    if args.cmd == "verify":
        obj = json.loads(Path(args.file).read_text(encoding="utf-8"))
        ok = verify_object(obj)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
