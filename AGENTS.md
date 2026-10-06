# awdit for agents

Read this if you are an agent (or a human) editing this package. Short on
purpose: the commands, the traps that cost a session, and where the rest lives.
Nothing here is read at runtime — it is for you.

## What this is

PyPI distribution **`awdit`** (version in `pyproject.toml`), import package
`awdit`, Python >= 3.10. An append-only audit trail whose gaps are
**DETECTABLE** — a hash-chained log where removal shows.

This repository is a **synced mirror** of the AitherOS monorepo (lane
`.github/workflows/sync-awdit.yml`). Hand edits made here are overwritten on
the next sync — change the source and let the lane publish.

## Build, test, verify

```bash
python -m pytest tests -q        # the suite: 6 tests, green at v0.1.0
pip install -e .                 # editable install for developing against it
```

The suite was run from a source checkout with no prior install. The publish
lane (`publish-brick.yml`) additionally builds the wheel, installs it and
imports it — a tree that tests green can still ship a broken wheel.

## Rules that keep this useful

- **Append-only is a structural property, not a policy.** Nothing rewrites or
  deletes a record; corrections are new records. Any code that edits history
  in place defeats the chain, and the chain is the product.
- **Truncation-evidence is the feature.** `test_chain.py` pins that a REMOVED
  tail or a missing middle is detectable from the remaining records — a log
  that can only prove what is present is not an audit trail.
- **The chain is small and boring on purpose.** Each change to the record
  shape is a format change for every consumer (awstorage's sweep receipts and
  adk's audit paths are among them); land it with the chain test updated in
  the same commit.
- **The registry drives the public surface.** This repo's README header,
  `llms.txt` and `aither-manifest.json` are generated from the ecosystem
  registry (one yaml in the AitherOS monorepo) and rewritten on every sync.
  Change the registry; do not hand-edit the generated blocks.

## Read next

- `llms.txt` — the install/use card written for an agent to execute
- `README.md` — the human front door
- `docs/` — the generated docs site source
