"""force-delete-asg-cascades-child-resources."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "force-delete-asg-cascades-child-resources"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


# timing:real-time — workflow: 30 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks-overview.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A plain DeleteAutoScalingGroup is rejected while a group instance and a warm pool instance
    are live; ForceDelete overrides that and cascades to the warm pool and lifecycle hooks."""
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet["subnet_id"],
        Tags=[{"Key": "sim2real-behav", "Value": group_name, "PropagateAtLaunch": True}],
    )

    def _safety_cleanup():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_safety_cleanup)

    asg.put_warm_pool(AutoScalingGroupName=group_name, MinSize=1, PoolState="Stopped")
    warm_pool = asg.describe_warm_pool(AutoScalingGroupName=group_name)
    assert warm_pool.get("WarmPoolConfiguration") is not None, "warm pool not visible after PutWarmPool"

    # HeartbeatTimeout is set to the API minimum: at the 3600s default the terminating instance
    # sits in Terminating:Wait for an hour before ForceDelete's cascade can finish. ForceDelete
    # removes the hook's configuration promptly but does not fast-forward an in-flight wait.
    hook_name = ctx.unique_name("sim2real-behav-hook-")
    asg.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING",
        HeartbeatTimeout=30,
    )
    hooks = asg.describe_lifecycle_hooks(AutoScalingGroupName=group_name)["LifecycleHooks"]
    assert any(h["LifecycleHookName"] == hook_name for h in hooks), "lifecycle hook not visible after PutLifecycleHook"

    def _group_instances():
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
        return groups[0]["Instances"] if groups else []

    _poll_until(
        _group_instances,
        lambda ins: bool(ins) and all(i["LifecycleState"] == "InService" for i in ins),
        timeout_s=420,
        interval_s=5,
        description="group instance reaching InService",
    )

    def _warm_pool_instances():
        return asg.describe_warm_pool(AutoScalingGroupName=group_name).get("Instances", [])

    _poll_until(
        _warm_pool_instances,
        lambda ins: bool(ins) and all(i["LifecycleState"] == "Warmed:Stopped" for i in ins),
        timeout_s=420,
        interval_s=10,
        description="warm pool instance reaching Warmed:Stopped",
    )

    # A plain delete must be rejected while both instances are live, and the group must survive
    # it, so ForceDelete below overrides a real block. With zero instances a plain delete
    # succeeds outright, which is why the group and warm pool are sized to hold an instance.
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=group_name)
    except ClientError as exc:
        no_force_error = exc.response["Error"]
    else:
        raise AssertionError("a plain delete with live instances attached unexpectedly succeeded")
    no_force_code = no_force_error["Code"]
    assert no_force_code == "ResourceInUse", (
        f"expected ResourceInUse rejecting a plain delete with live instances attached, got {no_force_code!r}"
    )
    in_use_message = (
        "You cannot delete an AutoScalingGroup while there are instances or pending Spot instance "
        "request(s) still in the group. Also, you can\u2019t delete it while there are instances "
        "that are part of a warm pool."
    )
    assert no_force_error.get("Message") == in_use_message, (
        f"expected message {in_use_message!r}, got {no_force_error.get('Message')!r}"
    )
    groups_still_there = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert groups_still_there, "a rejected plain delete must not remove the group"

    asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)

    _poll_until(
        lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"],
        lambda groups: groups == [],
        timeout_s=420,
        interval_s=10,
        description="group fully deleted after ForceDelete",
    )
    groups_after = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert groups_after == [], f"group still present after force delete: {groups_after}"

    # Once the group itself is gone, DescribeWarmPool/DescribeLifecycleHooks reject the now-unknown
    # group name with ValidationError rather than returning an empty body - that rejection is itself
    # confirmation the warm pool / hooks (which are scoped to the group) no longer exist.
    try:
        warm_pool_after = asg.describe_warm_pool(AutoScalingGroupName=group_name)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationError", (
            f"unexpected error describing warm pool after ForceDelete cascade: {exc}"
        )
        expected = f"AutoScalingGroup name not found - No such Auto Scaling group: {group_name}"
        assert exc.response["Error"].get("Message") == expected, (
            f"expected message {expected!r}, got {exc.response['Error'].get('Message')!r}"
        )
    else:
        assert warm_pool_after.get("WarmPoolConfiguration") is None, (
            f"warm pool still configured after ForceDelete cascade: {warm_pool_after}"
        )
        assert warm_pool_after.get("Instances", []) == [], (
            f"warm pool instances still present after ForceDelete cascade: {warm_pool_after}"
        )

    try:
        hooks_after = asg.describe_lifecycle_hooks(AutoScalingGroupName=group_name)["LifecycleHooks"]
    except ClientError as exc:
        # AWS answers this call with an empty list, so there is no refusal message to pin;
        # only the code is checked on this branch.
        assert exc.response["Error"]["Code"] == "ValidationError", (
            f"unexpected error describing lifecycle hooks after ForceDelete cascade: {exc}"
        )
    else:
        assert hooks_after == [], f"lifecycle hooks still present after ForceDelete cascade: {hooks_after}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {result!r}")


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"VPC {vpc_id} has no subnets to place the ASG in"
    subnet = subnets[0]
    return {"vpc_id": vpc_id, "subnet_id": subnet["SubnetId"]}


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        ec2 = ctx.client("ec2")
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": lt_name}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
