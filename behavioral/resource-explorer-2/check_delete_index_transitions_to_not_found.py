"""delete-index-transitions-to-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-index-transitions-to-not-found"
GROUP = "state-machine"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """DeleteIndex moves an ACTIVE index through DELETING to fully gone (GetIndex 404s)."""
    rex = ctx.client("resource-explorer-2")
    arn = _create_index_and_wait_active(ctx)

    deleted = rex.delete_index(Arn=arn)
    assert deleted["Arn"] == arn
    assert deleted["State"] in ("DELETING", "DELETED")

    # GetIndex does not necessarily 404 immediately (or ever, within this window) after
    # DeleteIndex -- it settles into a terminal DELETED state, which GetIndex continues to
    # report rather than raising ResourceNotFoundException. Accept either terminal signal.
    outcome = _poll_until(
        lambda: _get_index_state_or_code(ctx),
        lambda v: v in ("ResourceNotFoundException", "DELETED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert outcome in ("ResourceNotFoundException", "DELETED")

    # unusable, not just gone: a second DeleteIndex on the same dead arn is refused too --
    # ValidationException naming the DELETED state, not ResourceNotFoundException: the index
    # record persists in State=DELETED rather than disappearing, so a re-delete is refused with
    # ValidationException.
    second_delete_code, second_delete_message = _error_code_and_message(lambda: rex.delete_index(Arn=arn))
    assert second_delete_code == "ValidationException", (
        f"expected ValidationException re-deleting a terminal index, got {second_delete_code!r} "
        f"({second_delete_message!r})"
    )
    assert second_delete_message is not None and "DELETED" in second_delete_message, (
        f"expected the refusal to name the DELETED state, got message={second_delete_message!r}"
    )


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected a ClientError, call succeeded")
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _get_index_state_or_code(ctx):
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    try:
        return rex.get_index()["State"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _create_index_and_wait_active(ctx) -> str:
    rex = ctx.client("resource-explorer-2")
    arn = rex.create_index()["Arn"]

    def _cleanup() -> None:
        try:
            rex.delete_index(Arn=arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ValidationException" and _get_index_state_or_code(ctx) == "DELETED":
                return
            raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: rex.get_index()["State"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
