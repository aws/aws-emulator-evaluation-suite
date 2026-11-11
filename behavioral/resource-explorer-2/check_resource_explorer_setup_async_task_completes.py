"""resource-explorer-setup-async-task-completes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-explorer-setup-async-task-completes"
GROUP = "state-machine"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """CreateResourceExplorerSetup drives an async task whose per-Region Index/View sub-tasks
    reach SUCCEEDED, provisioning a real, usable index and view; deleting both then leaves
    them genuinely gone."""
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")

    try:
        existing = rex.get_index()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    else:
        # A deleted LOCAL index is not removed from GetIndex -- it reads back State=DELETED
        # forever (like a CFN stack's DELETE_COMPLETE), never ResourceNotFoundException.
        if existing.get("State") != "DELETED":
            raise AssertionError(
                f"an index already exists in this Region (Arn={existing.get('Arn')!r}, "
                f"State={existing.get('State')!r}, Type={existing.get('Type')!r}); "
                "CreateResourceExplorerSetup would conflict with pre-existing state, so this "
                "check needs a Region with no index"
            )

    view_name = ctx.unique_name("sim2real-rexsetup-")
    task_id = rex.create_resource_explorer_setup(RegionList=[ctx.region], ViewName=view_name)["TaskId"]

    result = _poll_until(
        lambda: rex.get_resource_explorer_setup(TaskId=task_id)["Regions"],
        lambda regions: (
            len(regions) == 1
            and regions[0]["Index"]["Status"] != "IN_PROGRESS"
            and regions[0]["View"]["Status"] != "IN_PROGRESS"
        ),
        timeout_s=180.0,
        interval_s=5.0,
    )
    region_result = result[0]
    assert region_result["Region"] == ctx.region, (
        f"expected the setup task to report region {ctx.region!r}, got {region_result['Region']!r}"
    )
    assert region_result["Index"]["Status"] == "SUCCEEDED", region_result["Index"].get("ErrorDetails")
    assert region_result["View"]["Status"] == "SUCCEEDED", region_result["View"].get("ErrorDetails")

    index_arn = region_result["Index"]["Index"]["Arn"]
    view_arn = region_result["View"]["View"]["ViewArn"]

    deleted_already = False

    def _cleanup() -> None:
        if deleted_already:
            return
        try:
            rex.delete_view(ViewArn=view_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            rex.delete_index(Arn=index_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    rex.tag_resource(resourceArn=index_arn, Tags={"env": "sim2real", "team": "qa"})
    rex.tag_resource(resourceArn=view_arn, Tags={"env": "sim2real", "team": "qa"})

    assert rex.get_index()["State"] == "ACTIVE", (
        "index provisioned by the setup task must be independently readable as ACTIVE, not just "
        "reported SUCCEEDED by the task itself"
    )
    got_view = rex.get_view(ViewArn=view_arn)["View"]
    assert got_view["ViewName"] == view_name, (
        f"expected view name {view_name!r} on independent GetView, got {got_view['ViewName']!r}"
    )

    rex.delete_view(ViewArn=view_arn)
    view_gone_code = _poll_until(
        lambda: _error_code(lambda: rex.get_view(ViewArn=view_arn)),
        lambda c: c in ("ResourceNotFoundException", "UnauthorizedException"),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert view_gone_code in ("ResourceNotFoundException", "UnauthorizedException"), (
        f"expected a deleted view to 404 on GetView, got {view_gone_code!r}"
    )

    rex.delete_index(Arn=index_arn)

    def _index_probe():
        try:
            return rex.get_index()["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise

    # GetIndex on a deleted LOCAL index does not 404 -- it keeps returning the index with
    # State=DELETED. Accept either shape, since which one real AWS takes is not this
    # check's contract to pin.
    index_gone_state = _poll_until(
        _index_probe,
        lambda s: s in ("GONE", "DELETED"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert index_gone_state in ("GONE", "DELETED"), (
        f"expected a deleted index to read back gone/DELETED via GetIndex, got {index_gone_state!r}"
    )
    deleted_already = True


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
