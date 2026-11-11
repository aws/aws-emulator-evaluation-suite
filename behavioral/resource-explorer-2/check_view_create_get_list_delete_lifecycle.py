"""view-create-get-list-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "view-create-get-list-delete-lifecycle"
GROUP = "view-lifecycle"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """CreateView persists a view with the requested Scope/Filters; ListViews surfaces it by
    ARN; DeleteView removes it so GetView and a second DeleteView are both refused."""
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    name = ctx.unique_name("sim2real-rexview-")
    _create_index_and_wait_active(ctx)
    created = rex.create_view(
        ViewName=name,
        Filters={"FilterString": "service:s3"},
        Tags={"sim2real-check": CHECK},
    )["View"]
    view_arn = created["ViewArn"]
    assert created["ViewName"] == name, f"expected ViewName={name!r}, got {created['ViewName']!r}"
    assert created["Filters"]["FilterString"] == "service:s3", (
        f"expected FilterString='service:s3', got {created['Filters']['FilterString']!r}"
    )
    owner = created["Owner"]

    deleted_already = False

    def _cleanup() -> None:
        if deleted_already:
            return
        try:
            rex.delete_view(ViewArn=view_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    fetched = rex.get_view(ViewArn=view_arn)["View"]
    assert fetched["ViewArn"] == view_arn, f"expected ViewArn={view_arn!r}, got {fetched['ViewArn']!r}"
    assert fetched["ViewName"] == name, f"expected ViewName={name!r}, got {fetched['ViewName']!r}"
    assert fetched["Owner"] == owner, f"expected Owner={owner!r} (from CreateView), got {fetched['Owner']!r}"

    all_view_arns: list[str] = []
    paginator_kwargs = {}
    while True:
        page = rex.list_views(**paginator_kwargs)
        all_view_arns.extend(page["Views"])
        token = page.get("NextToken")
        if not token:
            break
        paginator_kwargs = {"NextToken": token}
    assert view_arn in all_view_arns, f"expected {view_arn!r} in ListViews output, got {all_view_arns!r}"

    rex.delete_view(ViewArn=view_arn)
    deleted_already = True

    # DeleteView may be eventually consistent -- poll until GetView stops returning the view,
    # then grade the refusal. Real AWS answers a deleted view's ARN as UnauthorizedException.
    _poll_until(lambda: _view_visible(rex, view_arn), lambda visible: not visible, timeout_s=30.0, interval_s=2.0)
    expected = ("UnauthorizedException", "Unauthorized")
    get_error = _error(lambda: rex.get_view(ViewArn=view_arn))
    assert get_error == expected, f"expected GetView on deleted view to fail with {expected!r}, got {get_error!r}"

    # A mutation on the dead id must fail too, not just a read: double-delete proves the view is
    # gone-and-unusable, not merely absent from one read path.
    redelete_error = _error(lambda: rex.delete_view(ViewArn=view_arn))
    assert redelete_error == expected, (
        f"expected re-DeleteView on an already-deleted view to fail with {expected!r}, got {redelete_error!r}"
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
        arn = rex.create_index(Tags={"sim2real-check": CHECK})["Arn"]

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


def _view_visible(rex, arn) -> bool:
    """True while GetView still returns the view; False once GetView refuses it."""
    from botocore.exceptions import ClientError

    try:
        rex.get_view(ViewArn=arn)
    except ClientError:
        return False
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
