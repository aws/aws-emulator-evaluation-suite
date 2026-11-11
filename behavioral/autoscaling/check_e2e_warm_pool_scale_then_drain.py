"""e2e-warm-pool-scale-then-drain."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-warm-pool-scale-then-drain"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Raising DesiredCapacity moves a warm-pooled instance into service and out of the pool rather
    than launching a new one; identity proves it: the InService instance is one the pool prepared."""
    ec2 = ctx.client("ec2")
    asgc = ctx.client("autoscaling")

    ami_id = _latest_al2_ami(ctx)
    az = _first_az(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=3,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(lambda: _delete_asg_and_wait(ctx, asg_name))

    asgc.put_warm_pool(AutoScalingGroupName=asg_name, MinSize=1, MaxGroupPreparedCapacity=2, PoolState="Stopped")
    ctx.on_cleanup(lambda: _delete_warm_pool_and_wait(ctx, asg_name))

    # With DesiredCapacity=0 the pool's target size is MaxGroupPreparedCapacity (2).
    warm_before = _poll_warm_pool_ready(ctx, asg_name, min_count=2, timeout_s=300)
    warm_ids_before = {i["InstanceId"] for i in warm_before}
    assert warm_ids_before, "warm pool never prepared an instance"
    assert len(warm_ids_before) == 2, (
        f"expected the warm pool to prepare MaxGroupPreparedCapacity=2 instances, got {warm_ids_before}"
    )

    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    in_service = _poll_in_service(ctx, asg_name, min_count=1, timeout_s=180)
    in_service_ids = {i["InstanceId"] for i in in_service}
    assert in_service_ids, "no instance reached InService after scale-out"
    assert in_service_ids <= warm_ids_before, (
        f"expected the InService instance to be drawn from the warm pool {warm_ids_before}, "
        f"got a fresh launch {in_service_ids}"
    )

    expected_remaining = len(warm_ids_before) - len(in_service_ids)
    warm_after = _poll_warm_pool_count(ctx, asg_name, lambda n: n == expected_remaining, timeout_s=120)
    assert warm_after == expected_remaining, (
        f"warm pool count did not shrink by exactly the instances drawn into service "
        f"(before={len(warm_ids_before)}, drawn={len(in_service_ids)}, after={warm_after})"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return zones[0]["ZoneName"]


# "Warmed:Pending" and the bare "Pending" (shared with the main group's launching lifecycle,
# per the LifecycleState enum) mean the instance is still becoming warm, not ready -- only these
# three are the terminal "actually prepared" states DescribeWarmPool can report.
_WARM_READY_STATES = ("Warmed:Stopped", "Warmed:Running", "Warmed:Hibernated")
# Residual-in-pool counting (after a draw) is deliberately broader: an instance still mid-warm-up
# or mid-drain is not yet "drawn out", so it still counts against the pool.
_WARM_RESIDUAL_STATES = _WARM_READY_STATES + ("Warmed:Pending", "Pending")


def _poll_warm_pool_ready(ctx, asg_name: str, min_count: int, timeout_s: float):
    """Poll until at least min_count instances are prepared in the warm pool (not still
    launching) and return those instance records."""
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last: list = []
    while time.monotonic() < deadline:
        resp = asgc.describe_warm_pool(AutoScalingGroupName=asg_name)
        last = [i for i in resp.get("Instances", []) if i["LifecycleState"] in _WARM_READY_STATES]
        if len(last) >= min_count:
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"{min_count} warmed instances in {asg_name}: the run budget ended first; not graded"
        )
    return last


def _poll_warm_pool_count(ctx, asg_name: str, predicate, timeout_s: float):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        resp = asgc.describe_warm_pool(AutoScalingGroupName=asg_name)
        last = len([i for i in resp.get("Instances", []) if i["LifecycleState"] in _WARM_RESIDUAL_STATES])
        if predicate(last):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"the warm pool count of {asg_name} settling: the run budget ended first; not graded"
        )
    return last


def _poll_in_service(ctx, asg_name: str, min_count: int, timeout_s: float):
    """Poll until at least min_count instances are InService and return those records."""
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last: list = []
    while time.monotonic() < deadline:
        group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        last = [i for i in group.get("Instances", []) if i["LifecycleState"] == "InService"]
        if len(last) >= min_count:
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"{min_count} InService instances in {asg_name}: the run budget ended first; not graded"
        )
    return last


def _asg_not_found(exc) -> bool:
    """The group (or its warm pool) is already gone: autoscaling answers ValidationError."""
    err = getattr(exc, "response", {}).get("Error", {})
    msg = str(err.get("Message", "")).lower()
    return err.get("Code") == "ValidationError" and ("not found" in msg or "no warm pool found" in msg)


def _delete_warm_pool_and_wait(ctx, asg_name: str, timeout_s: float = 300.0) -> None:
    asgc = ctx.client("autoscaling")
    try:
        asgc.delete_warm_pool(AutoScalingGroupName=asg_name, ForceDelete=True)
    except Exception as exc:
        if _asg_not_found(exc):
            return
        raise RuntimeError(f"warm pool of {asg_name} was not deleted: {exc!r}") from exc
    last = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = asgc.describe_warm_pool(AutoScalingGroupName=asg_name)
        except Exception as exc:
            if _asg_not_found(exc):
                return
            last = exc
        else:
            if not resp.get("Instances") and resp.get("WarmPoolConfiguration") is None:
                return
            last = resp
        time.sleep(2)
    raise RuntimeError(f"warm pool of {asg_name} was not deleted: {last!r}")


def _delete_asg_and_wait(ctx, asg_name: str, timeout_s: float = 300.0) -> None:
    asgc = ctx.client("autoscaling")
    try:
        asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except Exception as exc:
        if _asg_not_found(exc):
            return
        raise RuntimeError(f"auto scaling group {asg_name} was not deleted: {exc!r}") from exc
    last = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        except Exception as exc:
            last = exc
        else:
            if not groups:
                return
            last = groups
        time.sleep(2)
    raise RuntimeError(f"auto scaling group {asg_name} was not deleted: {last!r}")


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
