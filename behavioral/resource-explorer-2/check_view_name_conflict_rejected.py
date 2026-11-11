"""view-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "view-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """CreateView with a name that already exists in the Region is rejected with
    ConflictException, the original view is unaffected, and creating a differently-named view
    still succeeds."""

    rex = ctx.client("resource-explorer-2")
    name = ctx.unique_name("sim2real-rexdupname-")
    _create_index_and_wait_active(ctx)
    original = rex.create_view(ViewName=name)["View"]
    original_arn = original["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, original_arn))

    error = _error(lambda: rex.create_view(ViewName=name))
    expected = (
        "ConflictException",
        "The request failed because either the request parameters didn't match to the original "
        "request or a view with the specified name already exists in this AWS Region.",
    )
    assert error == expected, f"expected {expected!r} for a duplicate ViewName, got {error!r}"

    # effect absent: the original view still exists, unchanged
    still_there = rex.get_view(ViewArn=original_arn)["View"]
    assert still_there["ViewArn"] == original_arn
    assert still_there["ViewName"] == name

    # positive control: a different name in the same Region succeeds
    other_name = ctx.unique_name("sim2real-rexdupname2-")
    other_arn = rex.create_view(ViewName=other_name)["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, other_arn))
    assert rex.get_view(ViewArn=other_arn)["View"]["ViewName"] == other_name


import time


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _create_index_and_wait_active(ctx) -> str:
    """Use the Region's index, creating one only when the account has none.

    The index is one per account and Region, so a pre-existing one is left exactly as found; only
    an index this check created is deleted at cleanup.
    """
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    try:
        existing = rex.get_index()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        existing = {}
    if existing.get("Arn") and existing.get("State") != "DELETED":
        arn = existing["Arn"]
    else:
        arn = rex.create_index()["Arn"]

        def _cleanup() -> None:
            rex.delete_index(Arn=arn)
            _poll_index_gone(ctx)

        ctx.on_cleanup(_cleanup)
    _poll_until(lambda: rex.get_index()["State"], lambda s: s == "ACTIVE", timeout_s=90.0, interval_s=3.0)
    return arn


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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete(rex, arn) -> None:
    from botocore.exceptions import ClientError

    try:
        rex.delete_view(ViewArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
