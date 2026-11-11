"""lifecycle-hook-full-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lifecycle-hook-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A lifecycle hook created with PutLifecycleHook is visible on DescribeLifecycleHooks
    and DescribeLifecycleHookTypes, accepts a heartbeat/completion callback, and is gone
    from DescribeLifecycleHooks after DeleteLifecycleHook."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    asg_name = ctx.unique_name("sim2real-asg-")
    lt_name = ctx.unique_name("sim2real-lt-")
    hook_name = ctx.unique_name("sim2real-hook-")

    ami_id = _latest_al2023_ami(ctx)
    subnet_ids, _vpc_id = _default_subnets(ctx)
    _create_launch_template(ctx, lt_name, ami_id)
    _create_zero_capacity_asg(ctx, asg_name, lt_name, subnet_ids)

    autoscaling.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300,
        DefaultResult="ABANDON",
    )
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: autoscaling.delete_lifecycle_hook(
            LifecycleHookName=hook_name, AutoScalingGroupName=asg_name
        ), "ValidationError", message="No Lifecycle Hook found")
    )

    hooks = autoscaling.describe_lifecycle_hooks(AutoScalingGroupName=asg_name)[
        "LifecycleHooks"
    ]
    matching = [h for h in hooks if h["LifecycleHookName"] == hook_name]
    assert len(matching) == 1, f"expected exactly one hook named {hook_name}"
    hook = matching[0]
    assert hook["LifecycleTransition"] == "autoscaling:EC2_INSTANCE_LAUNCHING"
    assert hook["DefaultResult"] == "ABANDON"
    assert hook["HeartbeatTimeout"] == 300

    hook_types = autoscaling.describe_lifecycle_hook_types()["LifecycleHookTypes"]
    assert "autoscaling:EC2_INSTANCE_LAUNCHING" in hook_types
    assert "autoscaling:EC2_INSTANCE_TERMINATING" in hook_types

    # The lifecycle hook is only meaningful while an instance is actually
    # transitioning through it, so scale the (previously zero-capacity) group up to
    # one instance now that the hook is attached: the new instance will be launched
    # and then held in Pending:Wait until the hook is completed.
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )

    def _group() -> dict:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
        assert len(groups) == 1
        return groups[0]

    def _pending_wait_instance_id():
        for i in _group()["Instances"]:
            if i["LifecycleState"] == "Pending:Wait":
                return i["InstanceId"]
        return None

    instance_id = _poll_for_value(
        _pending_wait_instance_id, timeout_s=300, interval_s=10
    )
    assert instance_id, (
        "no instance reached the Pending:Wait lifecycle state (hook never engaged) "
        "within 300s"
    )
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    def _instance_state(iid):
        for i in _group()["Instances"]:
            if i["InstanceId"] == iid:
                return i["LifecycleState"]
        return None

    heartbeat_resp = autoscaling.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        InstanceId=instance_id,
    )
    assert heartbeat_resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    post_heartbeat_state = _instance_state(instance_id)
    assert post_heartbeat_state == "Pending:Wait", (
        "a heartbeat must not itself advance the instance out of the wait state, "
        f"got {post_heartbeat_state!r}"
    )

    complete_resp = autoscaling.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id,
    )
    assert complete_resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    def _post_complete_state():
        state = _instance_state(instance_id)
        return None if state in (None, "Pending:Wait") else state

    released_state = _poll_for_value(_post_complete_state, timeout_s=180, interval_s=5)
    assert released_state == "InService", (
        "instance never resolved to InService after CompleteLifecycleAction, "
        f"last observed state {released_state!r}"
    )

    autoscaling.delete_lifecycle_hook(
        LifecycleHookName=hook_name, AutoScalingGroupName=asg_name
    )
    remaining = autoscaling.describe_lifecycle_hooks(AutoScalingGroupName=asg_name)[
        "LifecycleHooks"
    ]
    assert all(h["LifecycleHookName"] != hook_name for h in remaining), (
        "deleted hook still present in DescribeLifecycleHooks"
    )


def _poll_for_value(probe, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(interval_s)
    return probe()


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnets(ctx, count: int = 2):

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]], subnets[0]["VpcId"]


def _create_launch_template(ctx, lt_name: str, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    return lt_name


def _create_zero_capacity_asg(ctx, asg_name: str, lt_name: str, subnet_ids) -> str:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
