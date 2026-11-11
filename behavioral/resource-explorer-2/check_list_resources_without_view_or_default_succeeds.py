"""list-resources-without-view-or-default-succeeds."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resources-without-view-or-default-succeeds"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """ListResources with no ViewArn and no default view in the Region succeeds with a Resources
    list, and the same call with an explicit ViewArn succeeds and echoes that ViewArn.
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

    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexnolr-"), Tags={"sim2real:managed": "true"}
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view_arn))

    default_view = rex.get_default_view()
    assert "ViewArn" not in default_view, f"expected no default view configured, got {default_view!r}"

    resp_no_view = rex.list_resources()
    assert isinstance(resp_no_view.get("Resources"), list), (
        f"ListResources with no ViewArn and no default view must succeed (200) with a Resources "
        f"list, contrary to documentation claiming 401; got {resp_no_view!r}"
    )

    # positive control: an explicit ViewArn succeeds even with no default view set
    resp = rex.list_resources(ViewArn=view_arn)
    assert resp["ViewArn"] == view_arn, f"expected ViewArn {view_arn!r} echoed back, got {resp.get('ViewArn')!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


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
    arn = rex.create_index(Tags={"sim2real:managed": "true"})["Arn"]

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
