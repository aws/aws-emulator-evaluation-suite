"""e2e-instance-refresh-warm-pool-flow."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-instance-refresh-warm-pool-flow"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An instance refresh on a group with a warm pool succeeds with desired capacity held
    constant, then a ForceDelete of the group also removes its warm pool."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-lt-refresh-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id),
                                        "InvalidLaunchTemplateId.NotFound"))

    asg_name = ctx.unique_name("sim2real-asg-refresh-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=1,
        MaxSize=2,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=asg_name, ForceDelete=True
    )))

    def _group() -> dict[str, Any]:
        return autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]

    _poll_until(
        _group,
        lambda g: len(g["Instances"]) == 1 and g["Instances"][0]["LifecycleState"] == "InService",
        timeout_s=300,
        interval_s=15,
    )

    autoscaling.put_warm_pool(AutoScalingGroupName=asg_name, MinSize=1, PoolState="Stopped")

    def _warm_pool() -> dict[str, Any]:
        return autoscaling.describe_warm_pool(AutoScalingGroupName=asg_name)

    warm = _poll_until(
        _warm_pool, lambda wp: len(wp.get("Instances", [])) >= 1, timeout_s=300, interval_s=15
    )
    assert len(warm["Instances"]) >= 1, f"expected at least 1 warm pool instance, got {warm}"

    before_capacity = _group()["DesiredCapacity"]
    assert before_capacity == 1, f"expected DesiredCapacity 1 before the refresh, got {before_capacity}"

    refresh_id = autoscaling.start_instance_refresh(AutoScalingGroupName=asg_name)[
        "InstanceRefreshId"
    ]

    def _refresh() -> dict[str, Any]:
        resp = autoscaling.describe_instance_refreshes(
            AutoScalingGroupName=asg_name, InstanceRefreshIds=[refresh_id]
        )
        return resp["InstanceRefreshes"][0]

    terminal = {"Successful", "Failed", "Cancelled", "RollbackFailed", "RollbackSuccessful"}
    observed_in_progress_capacity = None
    deadline = time.monotonic() + 900
    refresh = _refresh()
    while refresh["Status"] not in terminal:
        if refresh["Status"] == "InProgress":
            observed_in_progress_capacity = _group()["DesiredCapacity"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance refresh did not reach a terminal state: {refresh}")
        time.sleep(2)
        refresh = _refresh()
    assert refresh["Status"] == "Successful", f"instance refresh ended as {refresh['Status']}"
    if observed_in_progress_capacity is not None:
        assert observed_in_progress_capacity == before_capacity, (
            f"desired capacity must hold constant during the refresh: observed "
            f"{observed_in_progress_capacity} in progress, expected {before_capacity}"
        )

    after_capacity = _group()["DesiredCapacity"]
    assert after_capacity == before_capacity, (
        f"desired capacity must be unchanged after the refresh: got {after_capacity}, "
        f"expected {before_capacity}"
    )

    # Cascading delete: ForceDelete on the group also deletes its warm pool.
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)

    def _group_gone() -> bool:
        resp = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        return len(resp["AutoScalingGroups"]) == 0

    _poll_until(_group_gone, lambda gone: gone, timeout_s=300, interval_s=10)

    # The cascade claim covers the warm pool too: once the group itself is gone, DescribeWarmPool
    # for that name is either empty or rejects the now-unknown group with ValidationError - either
    # is confirmation the warm pool (scoped to the group) no longer exists.
    try:
        warm_after = autoscaling.describe_warm_pool(AutoScalingGroupName=asg_name)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationError", (
            f"unexpected error describing warm pool after cascading ForceDelete: {exc}"
        )
        expected = f"AutoScalingGroup name not found - No such Auto Scaling group: {asg_name}"
        assert exc.response["Error"].get("Message") == expected, (
            f"expected message {expected!r}, got {exc.response['Error'].get('Message')!r}"
        )
    else:
        assert warm_after.get("Instances", []) == [], (
            f"warm pool instances still present after cascading ForceDelete: {warm_after}"
        )
        assert warm_after.get("WarmPoolConfiguration") is None, (
            f"warm pool configuration still present after cascading ForceDelete: {warm_after}"
        )


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


def _unless_gone(fn, *not_found):
    """Run one cleanup call; only a not-found answer means the resource is already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in not_found or (
                err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            return
        raise


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
