"""delete-default-view-clears-default-pointer."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-default-view-clears-default-pointer"
GROUP = "view-lifecycle"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """Deleting the Region's default view clears the pointer: GetDefaultView then returns no
    ViewArn, GetView on the deleted view is refused as Unauthorized, and AssociateDefaultView on it
    is refused with ResourceNotFoundException naming the ARN.
    """

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)

    # GetDefaultView does NOT throw when no default is set -- it returns 200 with no
    # "ViewArn" key in the body. Detect absence by key presence, not by exception.
    prior_default = rex.get_default_view().get("ViewArn")
    had_prior_default = prior_default is not None

    def _restore_prior_default() -> None:
        if had_prior_default:
            rex.associate_default_view(ViewArn=prior_default)

    ctx.on_cleanup(_restore_prior_default)

    view_arn = rex.create_view(ViewName=ctx.unique_name("sim2real-rexdefdel-"))["View"]["ViewArn"]
    rex.associate_default_view(ViewArn=view_arn)
    got = rex.get_default_view()
    assert got.get("ViewArn") == view_arn, f"expected default view {view_arn!r}, got {got!r}"

    rex.delete_view(ViewArn=view_arn)

    after = rex.get_default_view()
    assert "ViewArn" not in after, (
        f"expected default-view pointer cleared after deleting the default view, got {after!r}"
    )

    # The deleted view is independently gone, not merely unpointed-to -- GetView may be
    # eventually consistent, so poll until it refuses before grading the refusal.
    def _view_refused() -> bool:
        try:
            rex.get_view(ViewArn=view_arn)
        except ClientError:
            return True
        return False

    _poll_until(_view_refused, bool, timeout_s=30.0, interval_s=2.0)
    get_code, get_message = _error(lambda: rex.get_view(ViewArn=view_arn))
    assert get_code == "UnauthorizedException", (
        f"expected GetView on the deleted view to be refused, got {(get_code, get_message)!r}"
    )
    expected_get_message = "Unauthorized"
    assert get_message == expected_get_message, (
        f"expected GetView message {expected_get_message!r}, got {get_message!r}"
    )

    # ...and it cannot be re-pointed-to as the default either.
    reassoc_code, reassoc_message = _error(lambda: rex.associate_default_view(ViewArn=view_arn))
    expected_reassoc = ("ResourceNotFoundException", f"Views Not Found for provided arn: {view_arn}")
    assert (reassoc_code, reassoc_message) == expected_reassoc, (
        f"expected AssociateDefaultView on the deleted view to fail, got {(reassoc_code, reassoc_message)!r}"
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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
