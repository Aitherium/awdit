"""Verify a chain, and say which of the three failures happened.

They are genuinely different and an audit tool that folds them into one
"invalid" is not much use during an incident:

  * ALTERED    — a record's stored hash does not match its content.
  * REORDERED  — a record's `prev` does not match the previous record's hash.
  * TRUNCATED  — the chain is internally perfect but SHORTER than the anchor.

Only the third needs the anchor, and it is the one a plain hash chain cannot see
at all. A verifier that reports "ok" on a truncated log is worse than no
verifier, because it converts a missing record into a positive assurance.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .log import GENESIS, digest_record, read, read_anchor


@dataclass
class Result:
    ok: bool
    count: int = 0
    head: str = GENESIS
    problems: list[str] = field(default_factory=list)
    #: True only when the log is internally consistent AND matches its anchor.
    #: Kept separate from `ok` so a caller can tell "the chain is fine but I
    #: could not check for truncation" from "the chain is fine, fully checked".
    anchored: bool = False

    def __bool__(self) -> bool:  # so `if verify(path):` reads correctly
        return self.ok


def verify(log_path: str | os.PathLike[str]) -> Result:
    prev = GENESIS
    count = 0
    problems: list[str] = []

    for rec in read(log_path):
        count += 1
        if rec.get("__unparseable__"):
            problems.append(f"record {count}: line {rec['line']} does not parse as JSON")
            # Cannot continue the chain past a record we cannot read: every
            # later record would be reported broken for someone else's reason.
            return Result(ok=False, count=count, head=prev, problems=problems)

        stored = rec.get("hash")
        body = {k: rec[k] for k in ("ts", "event", "prev", "data") if k in rec}
        expected = digest_record(rec.get("prev", ""), body)

        if stored != expected:
            problems.append(
                f"record {count} ALTERED: content does not match its own hash "
                f"(event={rec.get('event')!r})"
            )
        if rec.get("prev") != prev:
            problems.append(
                f"record {count} REORDERED or a record was removed before it: "
                f"prev={rec.get('prev', '')[:12]}… expected {prev[:12]}…"
            )
        prev = stored or ""

    anchor = read_anchor(log_path)
    anchored = False
    if anchor is None:
        problems.append(
            "NO ANCHOR: the chain is self-consistent, but truncation of the tail "
            "is undetectable without one. This is a WARNING, not a pass."
        )
    elif anchor.get("corrupt"):
        problems.append("ANCHOR UNREADABLE: cannot check for truncation")
    else:
        anchored = True
        if anchor.get("count", 0) > count:
            problems.append(
                f"TRUNCATED: anchor records {anchor['count']} entries, log holds "
                f"{count} — {anchor['count'] - count} removed from the end"
            )
        elif anchor.get("head") != prev and count:
            problems.append(
                f"HEAD MISMATCH: anchor head {str(anchor.get('head'))[:12]}… but log "
                f"ends at {prev[:12]}… — the log moved without the anchor, or vice versa"
            )

    hard = [p for p in problems if not p.startswith("NO ANCHOR")]
    return Result(ok=not hard, count=count, head=prev, problems=problems, anchored=anchored)
