"""Append-only audit records, hash-chained.

Each record carries the digest of the one before it, so ALTERING or REORDERING
history breaks the chain at the point of the change and `awdit verify` names the
record. That much is ordinary.

The part that is usually got wrong is TRUNCATION. A hash chain proves that the
records you are holding follow one another; it says nothing about records that
used to be on the end and are not there now. Cutting the tail off a chained log
leaves a perfectly valid shorter chain — which is precisely the edit an attacker
who has just done something wants to make, and precisely the one a naive
"tamper-evident log" quietly permits.

So an anchor is a first-class part of this format, not an add-on: `append()`
maintains a sidecar holding the current head digest and record count. Verifying
against the anchor turns truncation from undetectable into a named failure. If
the anchor lives on the same disk as the log, an attacker with write access
edits both — that is stated in the README rather than papered over, because a
security property nobody can state the limits of is not one you can rely on.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Iterator

#: The digest a chain starts from. Fixed, so an empty log has a defined head
#: rather than a None that every caller has to special-case.
GENESIS = "0" * 64

ANCHOR_SUFFIX = ".anchor"


def _canonical(payload: dict[str, Any]) -> bytes:
    """Bytes a digest is taken over.

    `sort_keys` + no whitespace: two dicts that differ only in key order or
    formatting must produce the SAME digest, or a log rewritten by a different
    json writer would read as tampered and the alarm would mean nothing.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_record(prev: str, body: dict[str, Any]) -> str:
    """Chain digest: prev-hash bound INTO the record's own hash.

    Binding `prev` in is what makes it a chain rather than a list of independent
    hashes — reordering two records changes both digests, so a swap cannot be
    hidden by swapping their stored hashes too.
    """
    h = hashlib.sha256()
    h.update(prev.encode("ascii"))
    h.update(b"\x00")
    h.update(_canonical(body))
    return h.hexdigest()


def anchor_path(log_path: str | os.PathLike[str]) -> Path:
    return Path(str(log_path) + ANCHOR_SUFFIX)


def read_anchor(log_path: str | os.PathLike[str]) -> dict[str, Any] | None:
    p = anchor_path(log_path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # A corrupt anchor is NOT "no anchor". Returning None here would make an
        # unreadable anchor indistinguishable from a log that never had one, and
        # those call for opposite responses.
        return {"corrupt": True}


def head(log_path: str | os.PathLike[str]) -> tuple[str, int]:
    """(head digest, record count) by reading the log itself."""
    prev, n = GENESIS, 0
    for rec in read(log_path):
        prev = rec.get("hash", "")
        n += 1
    return prev, n


#: How far back from the end `_anchored_head` looks for the last record. A record
#: longer than this falls back to the full read; it is never a wrong answer.
TAIL_BYTES = 65536


def _anchored_head(path: Path) -> tuple[str, int] | None:
    """(head, count) from the anchor, in constant time -- or None to read the log.

    Reading the whole log to find its head makes every append cost as much as
    the log is long, so a log written on a busy path gets slower all day. The
    anchor already holds the answer; the only question is whether it can be
    believed, and that is checked against the log itself: the LAST record on
    disk must be the one the anchor names.

    Every doubt answers None, and the caller reads the log: no anchor, a
    corrupt one, a torn last line, a last record that does not parse or carries
    a different hash (an append died between the record and the anchor, or
    somebody edited the tail). Nothing here can make a tampered log look whole;
    it only declines to take the short cut.
    """
    anchor = read_anchor(path)
    if not anchor or anchor.get("corrupt"):
        return None
    want, count = anchor.get("head"), anchor.get("count")
    if not isinstance(want, str) or type(count) is not int or count <= 0:
        return None
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            back = min(size, TAIL_BYTES)
            fh.seek(size - back)
            tail = fh.read(back)
    except OSError:
        return None
    if not tail.endswith(b"\n"):
        return None
    body = tail[:-1]
    cut = body.rfind(b"\n")
    if cut < 0 and back < size:
        return None                      # the last record is longer than the window
    try:
        last = json.loads(body[cut + 1:])
    except ValueError:
        return None
    if not isinstance(last, dict) or last.get("hash") != want:
        return None
    return want, count


def append(log_path: str | os.PathLike[str], event: str, **fields: Any) -> dict[str, Any]:
    """Append one record and update the anchor. Returns the stored record."""
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev, count = _anchored_head(path) or head(path)
    body = {"ts": time.time(), "event": event, "prev": prev, "data": fields}
    record = dict(body)
    record["hash"] = digest_record(prev, body)

    # The record lands BEFORE the anchor moves. If the process dies between the
    # two, verification reports an anchor behind the log — recoverable, and
    # obviously so. The other order loses a record while claiming completeness.
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    anchor_path(path).write_text(
        json.dumps({"head": record["hash"], "count": count + 1}, sort_keys=True),
        encoding="utf-8",
    )
    return record


def read(log_path: str | os.PathLike[str]) -> Iterator[dict[str, Any]]:
    """Yield records. A line that does not parse is yielded as a marker rather
    than skipped — a silently dropped line is a gap the chain check would then
    blame on the NEXT record."""
    p = Path(log_path)
    if not p.is_file():
        return
    with p.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                yield {"__unparseable__": True, "line": i, "raw": line[:200]}
