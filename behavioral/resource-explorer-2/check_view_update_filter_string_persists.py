"""view-update-filter-string-persists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "view-update-filter-string-persists"
GROUP = "view-lifecycle"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """UpdateView replaces a view's Filters.FilterString and the new value -- not the old one --
    is what a subsequent GetView returns."""

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)
    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexupdview-"),
        Filters={"FilterString": "service:s3"},
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, view_arn))

    created_filter = rex.get_view(ViewArn=view_arn)["View"]["Filters"]["FilterString"]
    assert created_filter == "service:s3", (
        f"expected the just-created view's FilterString to be 'service:s3', got {created_filter!r}"
    )

    updated = rex.update_view(ViewArn=view_arn, Filters={"FilterString": "service:ec2"})["View"]
    assert updated["Filters"]["FilterString"] == "service:ec2", (
        f"expected UpdateView's own response to echo the new FilterString 'service:ec2', "
        f"got {updated['Filters']['FilterString']!r}"
    )

    refetched_filter = rex.get_view(ViewArn=view_arn)["View"]["Filters"]["FilterString"]
    assert refetched_filter == "service:ec2", (
        f"expected an independent GetView after UpdateView to return the new FilterString "
        f"'service:ec2', got {refetched_filter!r}"
    )
    assert refetched_filter != "service:s3", (
        f"expected the independent GetView to no longer return the pre-update FilterString "
        f"'service:s3', got {refetched_filter!r}"
    )


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
    rex = ctx.client("resource-explorer-2")

    def _probe():
        try:
            return rex.get_index()["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise

    _poll_until(_probe, lambda s: s in ("GONE", "DELETED"), timeout_s=timeout_s, interval_s=interval_s)


def _safe_delete(rex, arn) -> None:
    try:
        rex.delete_view(ViewArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
