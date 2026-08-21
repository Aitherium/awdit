"""awdit — an append-only audit trail whose gaps are detectable.

    from awdit import append, verify

    append("audit.log", "deploy", service="veil", by="david")
    r = verify("audit.log")
    if not r:
        for p in r.problems:
            print(p)

Part of the `aw` family (awgit, awgraph, awseal, awnode, awdk, …).
"""

from .log import GENESIS, append, head, read, read_anchor
from .verify import Result, verify

__version__ = "0.1.0"
__all__ = ["append", "read", "head", "read_anchor", "verify", "Result", "GENESIS"]
