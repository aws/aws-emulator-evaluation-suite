"""search-filtered-view-returns-deterministic-empty."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "search-filtered-view-returns-deterministic-empty"
GROUP = "search"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """Search through a view filtered to a resource type that cannot exist returns no resources with
    Count.TotalResources 0 and Complete true, while an unfiltered view on the same index finds
    resources.
    """

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)

    control_view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexctrl-"), Tags={"sim2real-check": CHECK}
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, control_view_arn))
    control_resp = rex.search(QueryString="", ViewArn=control_view_arn)
    assert control_resp["Count"]["TotalResources"] > 0, (
        "positive control: expected the unrestricted view to see indexed resources, got "
        f"Count={control_resp['Count']!r}"
    )

    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexsrch-"),
        Filters={"FilterString": "resourcetype:sim2realzz:doesnotexist"},
        Tags={"sim2real-check": CHECK},
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view_arn))

    resp = rex.search(QueryString="", ViewArn=view_arn)

    assert resp["Resources"] == [], f"expected no resources for an impossible resourcetype filter, got {resp['Resources']!r}"
    assert resp["ViewArn"] == view_arn, f"expected ViewArn {view_arn!r}, got {resp['ViewArn']!r}"
    assert resp["Count"]["TotalResources"] == 0, f"expected TotalResources == 0, got Count={resp['Count']!r}"
    assert resp["Count"]["Complete"] is True, f"expected an exhaustive (Complete) empty result, got Count={resp['Count']!r}"


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
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    created_here = False
    try:
        arn = rex.create_index(Tags={"sim2real-check": CHECK})["Arn"]
        created_here = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
        arn = rex.get_index()["Arn"]

    if created_here:
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
