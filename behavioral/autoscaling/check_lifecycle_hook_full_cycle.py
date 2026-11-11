"""lifecycle-hook-full-cycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lifecycle-hook-full-cycle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLifecycleHook holds a launching instance in Pending:Wait; heartbeat + Complete
    advances it to InService, and DeleteLifecycleHook removes the hook from the group."""
    asg = ctx.client("autoscaling")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_asg(ctx, group_name, lt_id, min_size=0, max_size=1, desired=0, subnet_id=subnet["subnet_id"])

    hook_name = ctx.unique_name("sim2real-behav-hook-")
    asg.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300,
        DefaultResult="ABANDON",
    )
    hooks = asg.describe_lifecycle_hooks(AutoScalingGroupName=group_name)["LifecycleHooks"]
    matching = [h for h in hooks if h["LifecycleHookName"] == hook_name]
    assert matching, "hook not visible after PutLifecycleHook"
    hook = matching[0]
    assert hook["LifecycleTransition"] == "autoscaling:EC2_INSTANCE_LAUNCHING", (
        f"LifecycleTransition not preserved: {hook['LifecycleTransition']!r}"
    )
    assert hook["HeartbeatTimeout"] == 300, f"HeartbeatTimeout not preserved: {hook['HeartbeatTimeout']!r}"
    assert hook["DefaultResult"] == "ABANDON", f"DefaultResult not preserved: {hook['DefaultResult']!r}"

    # Trigger a launch so the hook actually engages.
    asg.set_desired_capacity(AutoScalingGroupName=group_name, DesiredCapacity=1, HonorCooldown=False)

    instances_snapshot = _poll_until(
        lambda: _group_instances(ctx, group_name),
        lambda instances: any(i["LifecycleState"] == "Pending:Wait" for i in instances),
        timeout_s=240,
        interval_s=5,
    )
    waiting = [i for i in instances_snapshot if i["LifecycleState"] == "Pending:Wait"]
    assert waiting, "instance never entered Pending:Wait while the launch lifecycle hook was outstanding"
    iid = waiting[0]["InstanceId"]

    # Heartbeat should succeed without error while the action is outstanding.
    asg.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name, AutoScalingGroupName=group_name, InstanceId=iid
    )

    asg.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=iid,
    )

    final_state = _poll_until(
        lambda: next((i for i in _group_instances(ctx, group_name) if i["InstanceId"] == iid), None),
        lambda i: i is not None and i["LifecycleState"] == "InService",
        timeout_s=240,
        interval_s=5,
    )
    assert final_state is not None and final_state["LifecycleState"] == "InService", (
        f"instance never resolved to InService after CompleteLifecycleAction: {final_state}"
    )

    asg.delete_lifecycle_hook(LifecycleHookName=hook_name, AutoScalingGroupName=group_name)
    hooks_after = asg.describe_lifecycle_hooks(AutoScalingGroupName=group_name)["LifecycleHooks"]
    assert not any(h["LifecycleHookName"] == hook_name for h in hooks_after), (
        "hook still present in DescribeLifecycleHooks after DeleteLifecycleHook"
    )

    # The deleted hook must also be unusable, not merely absent from the list.
    try:
        result = asg.record_lifecycle_action_heartbeat(
            LifecycleHookName=hook_name, AutoScalingGroupName=group_name, InstanceId=iid
        )
    except ClientError as exc:
        dead_hook_code = exc.response.get("Error", {}).get("Code")
        dead_hook_message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"RecordLifecycleActionHeartbeat against a deleted hook SUCCEEDED: {result!r}"
        )
    assert dead_hook_code == "ValidationError", (
        f"RecordLifecycleActionHeartbeat against a deleted hook: expected ValidationError, got {dead_hook_code!r}"
    )
    expected_message = f"No active Lifecycle Action found with instance ID {iid}"
    assert dead_hook_message == expected_message, (
        f"expected message {expected_message!r}, got {dead_hook_message!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _group_instances(ctx, group_name: str) -> list[dict[str, Any]]:
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    return groups[0]["Instances"] if groups else []


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"no subnets available in VPC {vpc_id} to place the Auto Scaling group in"
    subnet = subnets[0]
    return {"vpc_id": vpc_id, "subnet_id": subnet["SubnetId"], "az": subnet["AvailabilityZone"]}


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
            {"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": lt_name}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, min_size: int, max_size: int, desired: int, subnet_id: str, **kwargs):
    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "Name", "Value": name, "PropagateAtLaunch": True}],
        **kwargs,
    )

    def _cleanup():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
