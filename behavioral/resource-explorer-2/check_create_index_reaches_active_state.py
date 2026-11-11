"""create-index-reaches-active-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-index-reaches-active-state"
GROUP = "state-machine"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """CreateIndex starts a LOCAL index that transitions CREATING/ACTIVE -> ACTIVE."""
    rex = ctx.client("resource-explorer-2")
    created = rex.create_index(Tags={"env": "sim2real", "team": "qa"})
    arn = created["Arn"]
    assert created["State"] in (
        "CREATING",
        "ACTIVE",
    ), f"CreateIndex returned unexpected initial state {created['State']!r}, expected CREATING or ACTIVE"

    def _cleanup() -> None:
        try:
            rex.delete_index(Arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        _poll_index_absent(ctx)

    ctx.on_cleanup(_cleanup)

    state = _poll_until(
        lambda: rex.get_index()["State"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert state == "ACTIVE", f"index did not settle into ACTIVE via GetIndex, last observed {state!r}"

    final = rex.get_index()
    assert final["Arn"] == arn, f"GetIndex Arn {final['Arn']!r} does not match created Arn {arn!r}"
    assert final["Type"] == "LOCAL", f"expected a LOCAL index, GetIndex reported Type={final['Type']!r}"
    assert (
        ctx.region in final["Arn"]
    ), f"index Arn {final['Arn']!r} does not embed the check's region {ctx.region!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _poll_index_absent(ctx, timeout_s=90.0, interval_s=3.0) -> None:
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
