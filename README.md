# awdit

An append-only audit trail whose **gaps are detectable**.

```bash
pip install awdit
```

```python
from awdit import append, verify

append("audit.log", "deploy", service="veil", by="david")

r = verify("audit.log")
if not r:
    for problem in r.problems:
        print(problem)
```

```bash
awdit append audit.log deploy --field service=veil
awdit verify audit.log        # 0 verified · 1 a real problem · 2 could not judge
awdit tail   audit.log -n 20
```

## What it actually proves

Records are hash-chained: each one binds the digest of the one before it, so
**altering** or **reordering** history breaks the chain at the point of the edit
and `verify` names the record. That much is ordinary.

The part usually got wrong is **truncation**. A hash chain proves the records
you are holding follow one another. It says nothing about records that used to
be on the end and are not there now — and cutting the tail off a chained log
leaves a perfectly valid shorter chain. That is exactly the edit someone who has
just done something wants to make, and exactly the one a naive "tamper-evident
log" permits in silence.

So the **anchor** is part of the format, not an add-on. `append()` maintains a
sidecar holding the head digest and the record count, and `verify` compares
against it:

```
TRUNCATED: anchor records 3 entries, log holds 2 — 1 removed from the end
```

Three failures, reported as three different things, because during an incident
they call for different responses:

| verdict | meaning |
|---|---|
| `ALTERED` | a record's content no longer matches its own hash |
| `REORDERED` | a record's `prev` does not match the previous record's hash |
| `TRUNCATED` | the chain is internally perfect but shorter than the anchor |

## What it does not prove — stated, not papered over

**If the anchor is on the same disk as the log, an attacker with write access
edits both.** The anchor turns truncation from *undetectable* into *detectable
by anyone who has a copy of the head*. To get a real guarantee, put the head
somewhere the writer cannot reach: another host, a signed artifact
([`awseal`](https://github.com/Aitherium/awseal)), a transparency log, a
sentence in a chat channel.

A security property whose limits nobody can state is not one you can rely on,
so: **this detects tampering, it does not prevent it**, and its truncation
detection is exactly as strong as the independence of the anchor.

`verify` also reports `NO ANCHOR` as a **warning that is not a pass** — a chain
with no anchor is self-consistent and truncatable, and reporting "ok" there
would convert a missing record into a positive assurance.

## Design notes

- **No dependencies.** An audit log that needs an install before it can be read
  is one nobody reads during an incident; `hashlib` and `json` are the whole
  requirement.
- **The record lands before the anchor moves.** If the process dies between the
  two, verification reports an anchor *behind* the log — recoverable and
  obvious. The other order loses a record while claiming completeness.
- **Digests are taken over canonical JSON** (sorted keys, no whitespace), so a
  log rewritten by a different writer does not read as tampered. An alarm that
  fires on formatting is an alarm nobody keeps.
- **An unparseable line is reported as itself**, not skipped — a silently
  dropped line becomes a chain gap blamed on the *next* record.

## Tests

Every claim has a mutation that breaks it, including one asserting that a
truncated chain with the anchor removed verifies **clean** — the proof that the
anchor is load-bearing rather than decoration.

```bash
pip install -e ".[dev]" && pytest
```

Part of the `aw` family: [awgit](https://github.com/Aitherium/awgit) ·
[awgraph](https://github.com/Aitherium/awgraph) ·
[awseal](https://github.com/Aitherium/awseal) ·
[awdk](https://github.com/Aitherium/awdk) ·
[awnode](https://github.com/Aitherium/awnode)

Apache-2.0.
