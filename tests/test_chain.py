"""Every claim awdit makes, with a mutation that breaks it.

A tamper-evident log is exactly the kind of thing that passes a happy-path test
while detecting nothing, so each test here EDITS the log and asserts the
specific verdict — not merely that something failed.
"""

import json

from awdit import append, verify


def test_clean_chain_verifies(tmp_path):
    log = tmp_path / "a.log"
    append(log, "created", who="david")
    append(log, "deployed", service="veil")
    r = verify(log)
    assert r.ok and r.count == 2 and r.anchored, r.problems


def test_altered_record_is_named(tmp_path):
    log = tmp_path / "a.log"
    append(log, "created")
    append(log, "deployed", service="veil")

    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["data"]["service"] = "something-else"          # content edited, hash left alone
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    r = verify(log)
    assert not r.ok
    assert any("ALTERED" in p for p in r.problems), r.problems


def test_reordering_is_named(tmp_path):
    log = tmp_path / "a.log"
    append(log, "one")
    append(log, "two")
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join([lines[1], lines[0]]) + "\n", encoding="utf-8")

    r = verify(log)
    assert not r.ok
    assert any("REORDERED" in p for p in r.problems), r.problems


def test_truncation_is_caught_only_because_of_the_anchor(tmp_path):
    """The reason the anchor exists. Cutting the tail leaves a chain that is
    internally PERFECT — without the anchor this is indistinguishable from a
    log that simply has fewer records."""
    log = tmp_path / "a.log"
    append(log, "one")
    append(log, "two")
    append(log, "three")

    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")   # drop the last

    r = verify(log)
    assert not r.ok
    assert any("TRUNCATED" in p for p in r.problems), r.problems

    # ...and prove the claim: with the anchor removed, the SAME truncated log is
    # internally consistent and nothing reports a hard failure.
    (tmp_path / "a.log.anchor").unlink()
    r2 = verify(log)
    assert r2.ok, "a truncated chain with no anchor is undetectable — that is the point"
    assert any("NO ANCHOR" in p for p in r2.problems)
    assert not r2.anchored


def test_unparseable_line_does_not_blame_the_next_record(tmp_path):
    log = tmp_path / "a.log"
    append(log, "one")
    append(log, "two")
    with log.open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    r = verify(log)
    assert not r.ok
    assert any("does not parse" in p for p in r.problems), r.problems
    assert not any("ALTERED" in p for p in r.problems), \
        "an unreadable line must not be reported as tampering by a later record"


def test_key_order_does_not_change_the_digest(tmp_path):
    """A log rewritten by a different json writer must not read as tampered, or
    the alarm means nothing."""
    log = tmp_path / "a.log"
    append(log, "e", b=2, a=1)
    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    log.write_text(json.dumps(rec, sort_keys=False, indent=None) + "\n", encoding="utf-8")
    assert verify(log).ok
