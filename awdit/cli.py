"""awdit CLI.

Exit codes are the contract: 0 verified, 1 a real problem, 2 could not judge.
`verify` on a missing file is 2, never 0 — an audit tool that reports success
for a log it never found is the one failure this package must not have.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .log import append, read
from .verify import verify


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="awdit", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("append", help="append a record")
    a.add_argument("log")
    a.add_argument("event")
    a.add_argument("--field", action="append", default=[], metavar="K=V")

    v = sub.add_parser("verify", help="verify the chain and its anchor")
    v.add_argument("log")
    v.add_argument("--json", action="store_true")

    t = sub.add_parser("tail", help="show the last N records")
    t.add_argument("log")
    t.add_argument("-n", type=int, default=10)

    args = ap.parse_args(argv)

    if args.cmd == "append":
        fields = {}
        for kv in args.field:
            if "=" not in kv:
                print(f"--field expects K=V, got {kv!r}", file=sys.stderr)
                return 2
            k, _, val = kv.partition("=")
            fields[k] = val
        rec = append(args.log, args.event, **fields)
        print(rec["hash"])
        return 0

    if args.cmd == "verify":
        if not Path(args.log).is_file():
            print(f"DEAD: no such log: {args.log} — cannot judge", file=sys.stderr)
            return 2
        r = verify(args.log)
        if args.json:
            print(json.dumps({"ok": r.ok, "count": r.count, "head": r.head,
                              "anchored": r.anchored, "problems": r.problems}, indent=2))
        else:
            print(f"{r.count} record(s), head {r.head[:16]}…, "
                  f"anchor {'checked' if r.anchored else 'ABSENT'}")
            for p in r.problems:
                print("  ! " + p)
            print("VERDICT:", "ok" if r.ok else "FAILED")
        return 0 if r.ok else 1

    if args.cmd == "tail":
        recs = [r for r in read(args.log)][-args.n:]
        for r in recs:
            print(json.dumps(r, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
