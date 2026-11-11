"""view-included-properties-reflected-in-get."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "view-included-properties-reflected-in-get"
GROUP = "view-lifecycle"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """A view created with IncludedProperties=[{Name: tags}] reports that property back on
    GetView, and UpdateView can clear it again."""

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)
    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexincl-"),
        IncludedProperties=[{"Name": "tags"}],
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, view_arn))

    created_props = rex.get_view(ViewArn=view_arn)["View"]["IncludedProperties"]
    assert [p["Name"] for p in created_props] == ["tags"], (
        f"expected an independent GetView after CreateView to report IncludedProperties=['tags'], "
        f"got {created_props!r}"
    )

    cleared = rex.update_view(ViewArn=view_arn, IncludedProperties=[])["View"]
    assert cleared["IncludedProperties"] == [], (
        f"expected UpdateView's own response to echo IncludedProperties=[] after clearing, "
        f"got {cleared['IncludedProperties']!r}"
    )

    refetched_props = rex.get_view(ViewArn=view_arn)["View"]["IncludedProperties"]
    assert refetched_props == [], (
        f"expected an independent GetView after the clearing UpdateView to report "
        f"IncludedProperties=[], got {refetched_props!r}"
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
    rex = ctx.client("resource-explorer-2")
    arn = rex.create_index()["Arn"]

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
