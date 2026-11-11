"""record-heartbeat-after-completion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "record-heartbeat-after-completion-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordLifecycleActionHeartbeat sent after CompleteLifecycleAction has already
    resolved the pending lifecycle action for an instance must be rejected, not silently
    accepted as if the action were still active."""
    asg = ctx.client("autoscaling")
    subnet_id = _get_default_subnet(ctx)
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": "behavioral", "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    hook_name = ctx.unique_name("sim2real-behav-hook-")
    asg.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300,
        DefaultResult="ABANDON",
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: asg.delete_lifecycle_hook(
                LifecycleHookName=hook_name, AutoScalingGroupName=group_name
            )
        )
    )

    asg.set_desired_capacity(AutoScalingGroupName=group_name, DesiredCapacity=1, HonorCooldown=False)

    def _pending_wait_probe():
        insts = asg.describe_auto_scaling_instances()["AutoScalingInstances"]
        return [i for i in insts if i["AutoScalingGroupName"] == group_name]

    matched = _poll_until(
        _pending_wait_probe,
        lambda items: any(i["LifecycleState"] == "Pending:Wait" for i in items),
        timeout_s=300,
        interval_s=5,
    )
    instance_id = next(i["InstanceId"] for i in matched if i["LifecycleState"] == "Pending:Wait")

    # Positive control: while the action is still open, a heartbeat is accepted and must NOT
    # itself release the instance. Without this, "rejected after completion" is indistinguishable
    # from "this target rejects every RecordLifecycleActionHeartbeat call".
    asg.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        InstanceId=instance_id,
    )
    still_open = _pending_wait_probe()
    assert any(
        i["InstanceId"] == instance_id and i["LifecycleState"] == "Pending:Wait" for i in still_open
    ), "a heartbeat on the still-open action must not itself advance the instance"

    asg.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id,
    )

    # Confirm the completion has actually taken effect server-side (the instance has left
    # the "Pending:Wait" state) before probing that a heartbeat is now rejected -- otherwise
    # this races against eventual consistency and can hit the hook while it still looks active.
    def _instance_state_probe():
        insts = asg.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
        return insts[0]["LifecycleState"] if insts else None

    _poll_until(
        _instance_state_probe,
        lambda s: s != "Pending:Wait",
        timeout_s=120,
        interval_s=5,
    )

    code, message = _error(
        lambda: asg.record_lifecycle_action_heartbeat(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=group_name,
            InstanceId=instance_id,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = f"No active Lifecycle Action found with instance ID {instance_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn) -> None:
    """Run a teardown delete; only an already-gone hook or group counts as clean."""
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        message = error.get("Message", "")
        if error["Code"] != "ValidationError" or not ("not found" in message or "No Lifecycle Hook found" in message):
            raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "behavioral"}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(30):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
