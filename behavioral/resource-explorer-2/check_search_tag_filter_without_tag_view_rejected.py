"""search-tag-filter-without-tag-view-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "search-tag-filter-without-tag-view-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """Search refuses a tag.key: filter with ValidationException once UpdateView drops the view's
    tags property, and accepts the same filter on the same view again once UpdateView restores it.
    """
    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)

    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rextagview-"),
        IncludedProperties=[{"Name": "tags"}],
        Tags={"sim2real-check": CHECK},
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view_arn))

    # positive control: the identical tag.key: filter succeeds while the view includes tags
    baseline = rex.search(QueryString="tag.key:sim2real-env", ViewArn=view_arn)
    assert baseline["ViewArn"] == view_arn, (
        f"expected baseline search to echo ViewArn {view_arn!r}, got {baseline.get('ViewArn')!r}"
    )

    # break exactly one thing: drop the view's tags property
    cleared_props = rex.update_view(ViewArn=view_arn, IncludedProperties=[])["View"]["IncludedProperties"]
    assert cleared_props == [], f"expected UpdateView to clear IncludedProperties, got {cleared_props!r}"

    error = _error(lambda: rex.search(QueryString="tag.key:sim2real-env", ViewArn=view_arn))
    expected = (
        "ValidationException",
        "The specified filter tag.key is not valid because it uses properties that are not "
        "included in the view.",
    )
    assert error == expected, f"expected {expected!r} once the view excludes tags, got {error!r}"

    # effect absent via an independent read: GetView confirms tags are still excluded
    refetched_props = rex.get_view(ViewArn=view_arn)["View"]["IncludedProperties"]
    assert refetched_props == [], (
        f"expected GetView to confirm no IncludedProperties after the break, got {refetched_props!r}"
    )

    # restore
    restored_props = rex.update_view(
        ViewArn=view_arn, IncludedProperties=[{"Name": "tags"}]
    )["View"]["IncludedProperties"]
    assert [p["Name"] for p in restored_props] == ["tags"], (
        f"expected UpdateView to restore IncludedProperties to ['tags'], got {restored_props!r}"
    )

    resp = rex.search(QueryString="tag.key:sim2real-env", ViewArn=view_arn)
    assert resp["ViewArn"] == view_arn, (
        f"expected the restored search to echo ViewArn {view_arn!r}, got {resp.get('ViewArn')!r}"
    )
    assert "Count" in resp, f"expected a Count block on the identical, now-accepted query, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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


def _safe_delete_view(rex, arn) -> None:
    from botocore.exceptions import ClientError

    try:
        rex.delete_view(ViewArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
