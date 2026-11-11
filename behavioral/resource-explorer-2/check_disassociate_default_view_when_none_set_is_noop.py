"""disassociate-default-view-when-none-set-is-noop."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-default-view-when-none-set-is-noop"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """DisassociateDefaultView with no default view set succeeds as a no-op and leaves none set, and
    associating then disassociating a real view sets and clears the default.
    """

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)

    prior_default = rex.get_default_view().get("ViewArn")
    had_prior_default = prior_default is not None
    if had_prior_default:
        rex.disassociate_default_view()

    def _restore_prior_default() -> None:
        if had_prior_default:
            rex.associate_default_view(ViewArn=prior_default)

    ctx.on_cleanup(_restore_prior_default)

    # setup: confirm no default view is currently set -- GetDefaultView returns 200 with no
    # "ViewArn" key in the body when unset; it does not raise ResourceNotFoundException here.
    baseline = rex.get_default_view()
    assert "ViewArn" not in baseline, f"expected no default view set, got {baseline!r}"

    # break (overly-permissive boundary): disassociating again while none is set does NOT error
    # -- it is a plain 200 no-op, empirically, not a ResourceNotFoundException. (The call not
    # raising is itself the assertion; an over-strict target would throw here.)
    rex.disassociate_default_view()

    # effect absent: still no default view set (state did not change)
    after_noop = rex.get_default_view()
    assert "ViewArn" not in after_noop, f"expected no default view after no-op disassociate, got {after_noop!r}"

    # positive control: associating and then disassociating a real view succeeds
    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexdisass-"), Tags={"sim2real-check": CHECK}
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, view_arn))

    rex.associate_default_view(ViewArn=view_arn)
    associated = rex.get_default_view()
    assert associated.get("ViewArn") == view_arn, f"expected default view {view_arn!r}, got {associated!r}"
    rex.disassociate_default_view()
    after_disassociate = rex.get_default_view()
    assert "ViewArn" not in after_disassociate, f"expected no default view after disassociate, got {after_disassociate!r}"


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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


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
