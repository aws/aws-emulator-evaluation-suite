"""e2e-scale-out-lifecycle-hook-scale-in-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-scale-out-lifecycle-hook-scale-in-teardown"
GROUP = "e2e"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A launch hook holds a scaling-out instance in Pending:Wait until CompleteLifecycleAction
    releases it; scale-in to zero empties the group and its deletion leaves the name dead."""
    ec2 = ctx.client("ec2")
    asgc = ctx.client("autoscaling")

    ami_id = _get_al2023_ami(ctx)
    subnet_id, _vpc_id = _get_default_subnet(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-hookasg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )

    def _cleanup_asg():
        try:
            asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            raise
        _poll_until_group_gone(ctx, asg_name, timeout_s=300)

    ctx.on_cleanup(_cleanup_asg)

    hook_name = ctx.unique_name("sim2real-behav-hook-")
    asgc.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300,
        DefaultResult="ABANDON",
    )

    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    # The launching instance must be held in Pending:Wait by the hook -- not launched straight
    # through to InService.
    instance_id = _poll_for_lifecycle_state(ctx, asg_name, "Pending:Wait", timeout_s=300)

    asgc.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name, AutoScalingGroupName=asg_name, InstanceId=instance_id
    )
    asgc.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        InstanceId=instance_id,
        LifecycleActionResult="CONTINUE",
    )

    # CompleteLifecycleAction(CONTINUE) must release the instance into InService.
    released_id = _poll_for_lifecycle_state(ctx, asg_name, "InService", timeout_s=300)
    assert released_id == instance_id, (
        f"expected the same instance {instance_id} to be released to InService, "
        f"got {released_id}"
    )
    ec2_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert ec2_state["State"]["Name"] == "running", (
        f"expected instance {instance_id} to be running at the EC2 layer after "
        f"CompleteLifecycleAction(CONTINUE), got {ec2_state['State']['Name']}"
    )

    # Scale back to zero must actually terminate the instance, not just relabel the group.
    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=0, HonorCooldown=False)
    _poll_until_instance_count(ctx, asg_name, expected=0, timeout_s=300)

    # DeleteAutoScalingGroup on an already-empty group must remove the group entirely.
    asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=False)
    _poll_until_group_gone(ctx, asg_name, timeout_s=180)

    # The name must be dead, not just absent from the list: a mutation against it must also fail.
    try:
        asgc.update_auto_scaling_group(AutoScalingGroupName=asg_name, MaxSize=3)
    except ClientError as exc:
        error = exc.response["Error"]
        assert (error["Code"], error["Message"]) == ("ValidationError", "AutoScalingGroup name not found - null"), (
            f"expected ValidationError 'AutoScalingGroup name not found' updating deleted "
            f"group {asg_name}, got {error['Code']}: {error['Message']}"
        )
    else:
        raise AssertionError(
            f"UpdateAutoScalingGroup on deleted group {asg_name} unexpectedly succeeded"
        )



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


def _poll_for_lifecycle_state(ctx, asg_name, target_state, timeout_s=300.0, interval_s=10.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        last = groups[0]["Instances"] if groups else []
        matches = [i for i in last if i["LifecycleState"] == target_state]
        if matches:
            return matches[0]["InstanceId"]
        time.sleep(interval_s)
    raise AssertionError(
        f"no instance in {asg_name} reached LifecycleState {target_state} after {timeout_s}s: {last}"
    )


def _poll_until_instance_count(ctx, asg_name, expected, timeout_s=300.0, interval_s=10.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        last = groups[0]["Instances"] if groups else []
        if len(last) == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected} instances in {asg_name}, observed {len(last)} after {timeout_s}s: {last}")


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
