"""delete-data-automation-library-twice-second-call-not-found-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-data-automation-library-twice-second-call-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the same Library a second time -- after it has fully transitioned out of DELETING
    and is gone -- is rejected with ResourceNotFoundException (not a silent success), while
    deleting a fresh, never-touched Library still succeeds (positive control)."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-lib-doubledel")
    arn = bda.create_data_automation_library(libraryName=name)["libraryArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, arn))

    bda.delete_data_automation_library(libraryArn=arn)

    # Deletion may be asynchronous (status transitions ACTIVE -> DELETING -> gone); wait for the
    # Library to be fully gone before probing the "delete an already-gone resource" boundary.
    _poll_until(
        lambda: _error_code(lambda: bda.get_data_automation_library(libraryArn=arn)),
        lambda code: code == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=2.0,
    )

    code, message = _rejected_code(lambda: bda.delete_data_automation_library(libraryArn=arn))
    assert code == "ResourceNotFoundException", f"unexpected code on second delete: {code}"
    assert message == "The specified library Arn not found.", f"unexpected message: {message!r}"

    # Effect confirmation: the Library is indeed gone, not left in some intermediate state.
    get_code, get_message = _rejected_code(lambda: bda.get_data_automation_library(libraryArn=arn))
    assert get_code == "ResourceNotFoundException"
    assert get_message == "The specified library Arn not found.", f"unexpected message: {get_message!r}"

    # Positive control: deleting a fresh Library succeeds cleanly.
    other_name = ctx.unique_name("sim2real-bda-lib-doubledel-other")
    other_arn = bda.create_data_automation_library(libraryName=other_name)["libraryArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, other_arn))
    bda.delete_data_automation_library(libraryArn=other_arn)
    other_gone = _poll_until(
        lambda: _error_code(lambda: bda.get_data_automation_library(libraryArn=other_arn)),
        lambda code: code == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert other_gone == "ResourceNotFoundException"


_SUCCEEDED = "<call succeeded>"


def _error_code(fn):
    """Poll probe: a success is a normal transient state (the Library is still leaving
    ACTIVE/DELETING), so it returns a sentinel no error code can equal."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return _SUCCEEDED


def _rejected_code(fn):
    """For a call real AWS is expected to reject. An unexpected SUCCESS here is the strongest signal
    available and must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call SUCCEEDED and returned {result!r}")


def _delete_ignore_missing(bda, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bda.delete_data_automation_library(libraryArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() <= deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
