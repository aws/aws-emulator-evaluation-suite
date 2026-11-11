"""concurrent-create-index-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-index-single-winner"
GROUP = "concurrency"
SERVICES = ["resource-explorer-2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """Only one index is allowed per Region: firing several concurrent CreateIndex calls in a
    Region with no index yields exactly one winner, and every other racer is rejected with
    ConflictException -- never two active indexes and never zero."""
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")

    try:
        rex.get_index()
        raise AssertionError(
            "an index already exists in this Region; the concurrent-create race can't be "
            "exercised cleanly without tearing down pre-existing state"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    n_racers = 6

    def _race(_i: int):
        try:
            return ("ok", rex.create_index()["Arn"])
        except ClientError as inner_exc:
            return ("error", inner_exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_race, range(n_racers)))

    winners = [arn for kind, arn in results if kind == "ok"]
    losers = [code for kind, code in results if kind == "error"]

    assert len(winners) == 1, f"expected exactly one winner, got {winners}"
    assert len(losers) == n_racers - 1, f"expected {n_racers - 1} losers, got {len(losers)}: {losers}"
    assert all(code == "ConflictException" for code in losers), (
        f"expected every loser to be ConflictException, got {losers}"
    )

    winning_arn = winners[0]

    def _cleanup() -> None:
        try:
            rex.delete_index(Arn=winning_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        _poll_index_gone(ctx)

    ctx.on_cleanup(_cleanup)

    state = _poll_until(
        lambda: rex.get_index()["State"], lambda s: s == "ACTIVE", timeout_s=90.0, interval_s=3.0
    )
    assert state == "ACTIVE", f"expected the winning index to reach ACTIVE, got {state!r}"
    final_arn = rex.get_index()["Arn"]
    assert final_arn == winning_arn, f"expected the surviving index to be the winner {winning_arn}, got {final_arn}"


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
