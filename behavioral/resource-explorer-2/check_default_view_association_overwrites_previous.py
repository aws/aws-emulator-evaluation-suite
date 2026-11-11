"""default-view-association-overwrites-previous."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "default-view-association-overwrites-previous"
GROUP = "view-lifecycle"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """AssociateDefaultView is idempotent-overwrite: pointing it at a second view replaces the
    first, and GetDefaultView always reflects the most recently associated view."""
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)
    view1_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexdv1-"), Tags={"sim2real": CHECK}
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view1_arn))
    view2_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexdv2-"), Tags={"sim2real": CHECK}
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view2_arn))

    # GetDefaultView does NOT raise when no default is set -- it returns 200 with no
    # "ViewArn" key in the body. Detect absence by key presence, not by exception.
    prior_default = rex.get_default_view().get("ViewArn")
    had_prior_default = prior_default is not None

    def _restore_prior_default() -> None:
        if had_prior_default:
            rex.associate_default_view(ViewArn=prior_default)
        else:
            try:
                rex.disassociate_default_view()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_restore_prior_default)

    rex.associate_default_view(ViewArn=view1_arn)
    got1 = rex.get_default_view()["ViewArn"]
    assert got1 == view1_arn, f"expected default view {view1_arn!r}, got {got1!r}"

    rex.associate_default_view(ViewArn=view2_arn)
    got2 = rex.get_default_view()["ViewArn"]
    assert got2 == view2_arn, f"expected default view to be overwritten to {view2_arn!r}, got {got2!r}"


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
    arn = rex.create_index(Tags={"sim2real": CHECK})["Arn"]

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
