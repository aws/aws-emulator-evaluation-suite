"""start-instance-refresh-during-warm-pool-deletion-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "start-instance-refresh-during-warm-pool-deletion-blocked"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWarmPool on a warm pool with live instances is rejected (ResourceInUse) without
    ForceDelete and the pool survives; during the async ForceDelete teardown, a concurrent
    StartInstanceRefresh on the same group is still accepted."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-lt-wpblock-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id)))

    asg_name = ctx.unique_name("sim2real-asg-wpblock-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-check",
                "Value": CHECK,
                "PropagateAtLaunch": False,
            }
        ],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=asg_name, ForceDelete=True
    )))

    autoscaling.put_warm_pool(AutoScalingGroupName=asg_name, MinSize=1, PoolState="Stopped")

    def _warm_pool() -> dict[str, Any]:
        return autoscaling.describe_warm_pool(AutoScalingGroupName=asg_name)

    warm = _poll_until(
        _warm_pool,
        lambda wp: len(wp.get("Instances", [])) >= 1
        and all(
            i["LifecycleState"] in {"Stopped", "Warmed:Stopped"} for i in wp["Instances"]
        ),
        timeout_s=420,
        interval_s=15,
    )
    assert len(warm["Instances"]) >= 1

    # Without ForceDelete, deleting a warm pool that still holds live instances is rejected.
    # DeleteWarmPool can transiently report ScalingActivityInProgress (settling instances) or
    # ResourceContention (racing the PutWarmPool call above); retry through both transient
    # wire-level codes (awsQuery drops the "Fault" suffix botocore's exception class carries)
    # and only assert on the steady-state response.
    _TRANSIENT_CODES = {"ScalingActivityInProgress", "ResourceContention"}
    code, message = _poll_until(
        lambda: _error(lambda: autoscaling.delete_warm_pool(AutoScalingGroupName=asg_name)),
        lambda cm: cm[0] not in _TRANSIENT_CODES,
        timeout_s=120,
        interval_s=5,
    )
    assert code == "ResourceInUse", f"unexpected code={code!r}"
    assert message == (
        "You cannot delete a warm pool while there are instances still in it unless you use "
        "the force delete option."
    ), f"unexpected ResourceInUse message: {message!r}"

    # Effect absent: the warm pool and its instance(s) are still present.
    warm = _warm_pool()
    assert len(warm.get("Instances", [])) >= 1

    # With ForceDelete, the (asynchronous) teardown is accepted.
    autoscaling.delete_warm_pool(AutoScalingGroupName=asg_name, ForceDelete=True)

    # A concurrent StartInstanceRefresh is accepted, not rejected as a resource conflict.
    refresh_id = autoscaling.start_instance_refresh(AutoScalingGroupName=asg_name)[
        "InstanceRefreshId"
    ]
    ctx.on_cleanup(lambda: _safe_call(lambda: autoscaling.cancel_instance_refresh(
        AutoScalingGroupName=asg_name
    )))
    refreshes = autoscaling.describe_instance_refreshes(
        AutoScalingGroupName=asg_name, InstanceRefreshIds=[refresh_id]
    )["InstanceRefreshes"]
    assert len(refreshes) == 1
    assert refreshes[0]["Status"] in {
        "Pending",
        "InProgress",
        "Baking",
        "Successful",
        "Cancelling",
        "Cancelled",
    }

    # Let the warm pool deletion finish (no instances left in the pool).
    def _warm_pool_empty() -> bool:
        return len(_warm_pool().get("Instances", [])) == 0

    _poll_until(_warm_pool_empty, lambda empty: empty, timeout_s=300, interval_s=15)


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet found in this account/region to launch ASG instances into"
        )
    return subnets[0]["SubnetId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


# The not-found codes of the teardown calls: the refresh, template or group is already gone.
_GONE_CODES = {"ActiveInstanceRefreshNotFound", "InvalidLaunchTemplateId.NotFound"}


def _safe_call(fn: Callable[[], Any]) -> None:
    """Run a teardown call; only an already-gone resource counts as clean."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] in _GONE_CODES:
            return
        if error["Code"] == "ValidationError" and "not found" in error.get("Message", ""):
            return
        raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(error code, error message) fn() raises. Raises if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 180.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
