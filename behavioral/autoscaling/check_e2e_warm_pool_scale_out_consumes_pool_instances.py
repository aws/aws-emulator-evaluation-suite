"""e2e-warm-pool-scale-out-consumes-pool-instances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-warm-pool-scale-out-consumes-pool-instances"
GROUP = "e2e"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On scale-out the ASG draws the same instance IDs from its pre-provisioned warm pool instead
    of launching fresh ones, and the warm pool shrinks by the same amount."""
    ec2 = ctx.client("ec2")
    asgc = ctx.client("autoscaling")

    ami_id = _get_al2023_ami(ctx)
    subnet_id, _vpc_id = _get_default_subnet(ctx)

    lt_name = ctx.unique_name("sim2real-behav-wplt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-wpasg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=5,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )

    def _cleanup_asg():
        try:
            asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            if not _gone(exc):
                raise
            return
        _poll_until_group_gone(ctx, asg_name, timeout_s=300)

    ctx.on_cleanup(_cleanup_asg)

    asgc.put_warm_pool(AutoScalingGroupName=asg_name, MinSize=2, MaxGroupPreparedCapacity=2, PoolState="Stopped")

    def _cleanup_warm_pool():
        try:
            asgc.delete_warm_pool(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            if not _gone(exc):
                raise

    ctx.on_cleanup(_cleanup_warm_pool)

    # PutWarmPool must actually provision 2 real, warmed (stopped) instances -- not just record config.
    warm_instances = _poll_warm_pool_ready(ctx, asg_name, expected=2, timeout_s=480)
    warm_ids_before = {i["InstanceId"] for i in warm_instances}
    assert len(warm_ids_before) == 2

    # Drop the pool's MinSize floor to 0 so that once instances are drawn out on scale-out, Auto
    # Scaling does not proactively relaunch replacements to refill the pool back up to a target
    # -- otherwise we would not be able to distinguish "drew from pool" from "pool refilled itself".
    asgc.put_warm_pool(AutoScalingGroupName=asg_name, MinSize=0, MaxGroupPreparedCapacity=2, PoolState="Stopped")

    # Scaling out must draw the SAME instances from the warm pool into the group, not launch fresh ones.
    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=2, HonorCooldown=False)
    in_service = _poll_until_instance_count(ctx, asg_name, expected=2, timeout_s=300)
    in_service_ids = {i["InstanceId"] for i in in_service}
    assert in_service_ids == warm_ids_before, (
        f"expected scale-out to draw from warm pool {warm_ids_before}, got fresh instances {in_service_ids}"
    )

    # The warm pool itself must shrink proportionally as instances are drawn out of it.
    remaining = _poll_warm_pool_count(ctx, asg_name, expected=0, timeout_s=300)
    assert remaining == 0


def _gone(exc) -> bool:
    """The group, or its warm pool, no longer exists."""
    err = exc.response["Error"]
    message = err.get("Message", "")
    return err["Code"] == "ValidationError" and ("not found" in message or "No warm pool found" in message)


def _get_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        resp = ssm.get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        )
        return resp["Parameter"]["Value"]
    except Exception as exc:  # pragma: no cover - defensive against missing SSM public parameter
        raise AssertionError(f"could not resolve a launchable AMI via the SSM public parameter: {exc}")


def _get_default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch instances into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch instances into")
    return subnets[0]["SubnetId"], vpc_id


def _poll_warm_pool_ready(ctx, asg_name, expected, timeout_s=480.0, interval_s=15.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        resp = asgc.describe_warm_pool(AutoScalingGroupName=asg_name)
        last = resp.get("Instances", [])
        ready = [i for i in last if i["LifecycleState"] in ("Warmed:Stopped", "Warmed:Running", "Warmed:Hibernated")]
        if len(ready) >= expected:
            return ready
        time.sleep(interval_s)
    raise AssertionError(f"warm pool for {asg_name} never reached {expected} warmed instances: {last}")


def _poll_warm_pool_count(ctx, asg_name, expected, timeout_s=180.0, interval_s=10.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = asgc.describe_warm_pool(AutoScalingGroupName=asg_name)
        instances = resp.get("Instances", [])
        # Only count instances still actually warmed/pending in the pool -- an instance that has
        # been drawn out and is transitioning (e.g. "Removing") is not a residual warm instance.
        warmed = [
            i for i in instances
            if i["LifecycleState"] in (
                "Warmed:Pending", "Warmed:Stopped", "Warmed:Running", "Warmed:Hibernated", "Pending",
            )
        ]
        last = len(warmed)
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"warm pool for {asg_name} never drained to {expected} instances, last observed {last}")


def _poll_until_instance_count(ctx, asg_name, expected, timeout_s=300.0, interval_s=10.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        last = groups[0]["Instances"] if groups else []
        in_service = [i for i in last if i["LifecycleState"] == "InService"]
        if len(in_service) >= expected:
            return in_service
        time.sleep(interval_s)
    raise AssertionError(
        f"expected {expected} InService instances in {asg_name}, observed {len(last)} after {timeout_s}s: {last}"
    )


def _poll_until_group_gone(ctx, asg_name, timeout_s=180.0, interval_s=10.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return
        time.sleep(interval_s)
    raise AssertionError(f"AutoScalingGroup {asg_name} was not removed after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
