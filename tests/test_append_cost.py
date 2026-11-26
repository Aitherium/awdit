"""An append must not cost as much as the log is long.

`append` used to read the whole log to find its head, so a log written on a busy
path got slower with every record. It now takes the head from the anchor when the
log's last record is the one the anchor names. These tests pin the two halves of
that: the short cut is actually taken, and every doubt about the anchor falls
back to reading the log -- it never makes a damaged log look whole.
"""

import json

import pytest
from awdit import append, log, read, verify


def _no_full_read(monkeypatch):
    def refuse(_path):
        raise AssertionError("append read the whole log")

    monkeypatch.setattr(log, "head", refuse)


def test_an_append_to_a_healthy_log_does_not_read_it(tmp_path, monkeypatch):
    path = tmp_path / "a.log"
    append(path, "first")                       # no anchor yet: the one full read
    _no_full_read(monkeypatch)
    for i in range(50):
        append(path, "next", i=i)
    r = verify(path)
    assert r.ok and r.count == 51 and r.anchored, r.problems


def test_the_short_cut_writes_the_same_chain_as_the_full_read(tmp_path, monkeypatch):
    fast, slow = tmp_path / "fast.log", tmp_path / "slow.log"
    monkeypatch.setattr(log.time, "time", lambda: 1_700_000_000.0)
    for i in range(20):
        append(fast, "e", i=i)
    monkeypatch.setattr(log, "_anchored_head", lambda _p: None)   # force the full read
    for i in range(20):
        append(slow, "e", i=i)
    assert fast.read_text("utf-8") == slow.read_text("utf-8")
    assert log.read_anchor(fast) == log.read_anchor(slow)


def test_a_record_longer_than_the_window_falls_back_and_stays_correct(tmp_path, monkeypatch):
    path = tmp_path / "a.log"
    monkeypatch.setattr(log, "TAIL_BYTES", 256)
    append(path, "small")
    append(path, "big", blob="x" * 4000)        # longer than the window
    assert log._anchored_head(path) is None
    append(path, "after")
    assert log._anchored_head(path) is not None  # a short last record: short cut again
    assert verify(path).ok and verify(path).count == 3


@pytest.mark.parametrize("damage", ["no_anchor", "corrupt_anchor", "stale_anchor",
                                    "torn_tail", "edited_tail", "bool_count", "zero_count"])
def test_any_doubt_about_the_anchor_reads_the_log(tmp_path, damage):
    path = tmp_path / "a.log"
    for i in range(3):
        append(path, "e", i=i)
    anchor = log.anchor_path(path)
    if damage == "no_anchor":
        anchor.unlink()
    elif damage == "corrupt_anchor":
        anchor.write_text("{not json", encoding="utf-8")
    elif damage == "stale_anchor":              # an append died before the anchor moved
        data = json.loads(anchor.read_text("utf-8"))
        anchor.write_text(json.dumps(dict(data, head="0" * 64, count=2)), encoding="utf-8")
    elif damage == "torn_tail":
        with path.open("ab") as fh:
            fh.write(b'{"event":"half')
    elif damage == "edited_tail":
        lines = path.read_text("utf-8").splitlines()
        rec = json.loads(lines[-1])
        rec["hash"] = "f" * 64
        path.write_text("\n".join(lines[:-1] + [json.dumps(rec)]) + "\n", encoding="utf-8")
    elif damage == "bool_count":
        data = json.loads(anchor.read_text("utf-8"))
        anchor.write_text(json.dumps(dict(data, count=True)), encoding="utf-8")
    elif damage == "zero_count":
        data = json.loads(anchor.read_text("utf-8"))
        anchor.write_text(json.dumps(dict(data, count=0)), encoding="utf-8")
    assert log._anchored_head(path) is None


def test_truncation_is_still_caught_after_short_cut_appends(tmp_path):
    path = tmp_path / "a.log"
    for i in range(5):
        append(path, "e", i=i)
    lines = path.read_text("utf-8").splitlines()
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")   # cut the tail off
    assert not verify(path).ok
    append(path, "after-the-cut")               # the anchor no longer matches: full read
    assert [r["event"] for r in read(path)][-1] == "after-the-cut"
