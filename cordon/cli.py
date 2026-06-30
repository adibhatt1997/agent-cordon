"""Command-line interface for cordon.

    cordon scan FILE [--json] [--strict] [--fail-over RISK]
    cat page.html | cordon scan -
    cordon sanitize FILE [--spotlight]
    cordon scan-action --tool http_post --arg url=https://x --arg body=@secret.txt
"""

from __future__ import annotations

import argparse
import json
import sys

from .egress import scan_action
from .policy import Policy
from .sanitize import sanitize, wrap_as_data
from .scanner import scan


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cordon",
        description="A quarantine line for the data your LLM agent ingests.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan text and report injection risk")
    s.add_argument("path", help="file path, or - for stdin")
    s.add_argument("--json", action="store_true")
    s.add_argument("--strict", action="store_true", help="use the strict policy")
    s.add_argument("--fail-over", type=int, default=None, metavar="RISK",
                   help="exit non-zero if risk >= RISK (for CI / pipelines)")

    sa = sub.add_parser("sanitize", help="print a defanged copy of the text")
    sa.add_argument("path")
    sa.add_argument("--spotlight", action="store_true",
                    help="datamark the content instead of inline flagging")

    ac = sub.add_parser("scan-action", help="check whether an outbound tool call is safe")
    ac.add_argument("--tool", required=True, help="tool name, e.g. http_post")
    ac.add_argument("--arg", action="append", default=[], metavar="K=V",
                    help="argument; value @file.txt reads from a file")
    ac.add_argument("--json", action="store_true")

    args = p.parse_args(argv)

    if args.command == "sanitize":
        text = _read(args.path)
        sys.stdout.write(wrap_as_data(text, use_spotlight=args.spotlight)
                         if args.spotlight else sanitize(text))
        return 0

    if args.command == "scan-action":
        kv = {}
        for item in args.arg:
            k, _, v = item.partition("=")
            if v.startswith("@"):
                v = _read(v[1:])
            kv[k] = v
        verdict = scan_action(args.tool, kv)
        if args.json:
            print(json.dumps({
                "allowed": verdict.allowed, "reasons": verdict.reasons,
                "secrets_found": verdict.secrets_found,
                "destinations": verdict.destinations,
            }, indent=2))
        else:
            print(verdict.summary())
        return 0 if verdict.allowed else 3

    # scan
    text = _read(args.path)
    policy = Policy.strict() if args.strict else None
    result = scan(text, policy)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.summary())
    if args.fail_over is not None and result.risk >= args.fail_over:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
