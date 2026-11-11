"""complete-lifecycle-action-unknown-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-lifecycle-action-unknown-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompleteLifecycleAction on a real hook with a never-issued LifecycleActionToken is rejected
    and the instance stays held; completing the same action by InstanceId then admits it.
    """
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
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": True}],
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
        lambda: _unless_gone(
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

    # A real hook and pending action isolate the token as the only unrecognized input.
    code, message = _client_error(
        lambda: asg.complete_lifecycle_action(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=group_name,
            LifecycleActionToken="00000000-0000-0000-0000-000000000000",
            LifecycleActionResult="CONTINUE",
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "No active Lifecycle Action found with token 00000000-0000-0000-0000-000000000000", f"expected the exact refusal message, got {message!r}"

    # Effect that must be ABSENT: the refused call may not have released the instance.
    def _instance_state_probe():
        insts = asg.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
        return insts[0]["LifecycleState"] if insts else "absent"

    state_after_refusal = _instance_state_probe()
    assert state_after_refusal == "Pending:Wait", (
        f"the refused unknown-token call advanced {instance_id}: {state_after_refusal!r}"
    )

    # Positive control: the same action addressed by InstanceId admits the instance.
    asg.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=group_name,
        LifecycleActionResult="CONTINUE",
        InstanceId=instance_id,
    )
    final_state = _poll_until(
        _instance_state_probe,
        lambda s: s == "InService",
        timeout_s=300,
        interval_s=5,
    )
    assert final_state == "InService", (
        f"the positive control did not admit {instance_id}: {final_state!r}"
    )
    ec2_state = _ec2_state(ctx, instance_id)
    assert ec2_state == "running", f"instance is InService but EC2 says {ec2_state!r}"




def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _unless_gone(fn) -> None:
    """Run a teardown step; only Auto Scaling's "not found" ValidationError means already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        if not (err["Code"] == "ValidationError" and ("not found" in msg or "No Lifecycle Hook found" in msg)):
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
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {"ResourceType": "instance",
                 "Tags": [{"Key": "sim2real:managed", "Value": "true"}]},
                {"ResourceType": "volume",
                 "Tags": [{"Key": "sim2real:managed", "Value": "true"}]},
            ],
        },
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _ec2_state(ctx, instance_id: str) -> str:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"]
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


def _delete_asg_force(ctx, name: str) -> None:
    """Force-delete the group, retrying in-progress refusals for 60 s; only "not found" means gone."""
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + 60
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ValidationError" and "not found" in err.response["Error"].get("Message", ""):
                return
            if code not in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
