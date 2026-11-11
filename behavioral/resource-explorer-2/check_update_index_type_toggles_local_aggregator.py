"""update-index-type-toggles-local-aggregator."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-index-type-toggles-local-aggregator"
GROUP = "state-machine"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """UpdateIndexType flips a LOCAL index to AGGREGATOR and back through ACTIVE/UPDATING."""
    rex = ctx.client("resource-explorer-2")
    arn = rex.create_index(Tags={"sim2real": CHECK})["Arn"]

    def _cleanup() -> None:
        try:
            rex.delete_index(Arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        _poll_index_gone(ctx)

    ctx.on_cleanup(_cleanup)

    _poll_until(lambda: rex.get_index()["State"], lambda s: s == "ACTIVE", timeout_s=90.0, interval_s=3.0)
    initial_type = rex.get_index()["Type"]
    assert initial_type == "LOCAL", f"expected fresh index Type=LOCAL, got {initial_type!r}"

    promoted = rex.update_index_type(Arn=arn, Type="AGGREGATOR")
    assert promoted["Type"] == "AGGREGATOR", f"expected UpdateIndexType response Type=AGGREGATOR, got {promoted['Type']!r}"
    assert promoted["State"] in ("UPDATING", "ACTIVE"), (
        f"expected UpdateIndexType response State in (UPDATING, ACTIVE), got {promoted['State']!r}"
    )

    state_after_promote = _poll_until(
        lambda: (rex.get_index()["State"], rex.get_index()["Type"]),
        lambda pair: pair == ("ACTIVE", "AGGREGATOR"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert state_after_promote == ("ACTIVE", "AGGREGATOR"), (
        f"expected independent get_index read to settle at (ACTIVE, AGGREGATOR), got {state_after_promote!r}"
    )

    demoted = rex.update_index_type(Arn=arn, Type="LOCAL")
    assert demoted["Type"] == "LOCAL", f"expected UpdateIndexType response Type=LOCAL, got {demoted['Type']!r}"

    state_after_demote = _poll_until(
        lambda: (rex.get_index()["State"], rex.get_index()["Type"]),
        lambda pair: pair == ("ACTIVE", "LOCAL"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert state_after_demote == ("ACTIVE", "LOCAL"), (
        f"expected independent get_index read to settle at (ACTIVE, LOCAL), got {state_after_demote!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _poll_index_gone(ctx, timeout_s=90.0, interval_s=3.0) -> None:
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")

    def _probe():
        try:
            return rex.get_index()["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise

    _poll_until(_probe, lambda s: s in ("GONE", "DELETED"), timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
