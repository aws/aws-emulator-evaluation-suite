"""list-deployments-history-filter-latest-only-vs-all."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-deployments-history-filter-latest-only-vs-all"
GROUP = "deployment-lifecycle"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeployments with historyFilter=LATEST_ONLY returns only the current deployment for
    a target, while historyFilter=ALL includes the superseded (INACTIVE) revision too."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    group_arn = iot.create_thing_group(
        thingGroupName=group_name, tags=[{"Key": "purpose", "Value": "sim2real-behavioral"}]
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    dep1_id = gg.create_deployment(
        targetArn=group_arn, tags={"purpose": "sim2real-behavioral"}
    )["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep1_id))
    dep2_id = gg.create_deployment(
        targetArn=group_arn, tags={"purpose": "sim2real-behavioral"}
    )["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep2_id))

    _poll_until(
        lambda: gg.get_deployment(deploymentId=dep1_id)["deploymentStatus"],
        lambda status: status != "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )

    latest_only_ids = {
        d["deploymentId"]
        for d in gg.list_deployments(targetArn=group_arn, historyFilter="LATEST_ONLY")["deployments"]
    }
    assert dep2_id in latest_only_ids, (
        f"expected current deployment {dep2_id} in LATEST_ONLY set {latest_only_ids}"
    )
    assert dep1_id not in latest_only_ids, (
        f"expected superseded deployment {dep1_id} excluded from LATEST_ONLY set {latest_only_ids}"
    )

    all_ids = {
        d["deploymentId"]
        for d in gg.list_deployments(targetArn=group_arn, historyFilter="ALL")["deployments"]
    }
    assert dep1_id in all_ids, f"expected superseded deployment {dep1_id} in ALL set {all_ids}"
    assert dep2_id in all_ids, f"expected current deployment {dep2_id} in ALL set {all_ids}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _cleanup_deployment(gg, deployment_id: str) -> None:
    deadline = time.monotonic() + 15.0
    try:
        gg.cancel_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        # A deployment that is not ACTIVE cannot be canceled; DeleteDeployment decides.
        if code not in ("ConflictException", "ValidationException"):
            raise
    while True:
        try:
            gg.delete_deployment(deploymentId=deployment_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # DeleteDeployment refuses ("must be canceled before deletion") until the cancel
            # has taken effect; retry only that refusal.
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
