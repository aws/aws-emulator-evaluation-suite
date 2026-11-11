"""deploy-scaling-policy-cloudformation-triggers-scaling."""
from __future__ import annotations

import json
import time

from botocore.exceptions import WaiterError

from behavioral_harness import tags

CHECK = "deploy-scaling-policy-cloudformation-triggers-scaling"
GROUP = "deploy"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A ScalingPolicy resource attached to an ASG in a CloudFormation stack, once executed via
    ExecutePolicy, produces a real capacity change and a recorded, Successful scaling activity
    -- not merely a PutScalingPolicy/ExecutePolicy 200 with no effect."""
    cfn = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    ami_id = _get_al2023_ami(ctx)
    subnet_id, _vpc_id = _get_default_subnet(ctx)

    stack_name = ctx.unique_name("sim2real-behav-asgpolcfn-")
    asg_name = ctx.unique_name("sim2real-behav-asgpol-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {
                        "ImageId": ami_id,
                        "InstanceType": "t3.micro",
                    }
                },
            },
            "ASG": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {
                    "AutoScalingGroupName": asg_name,
                    "MinSize": "0",
                    "MaxSize": "3",
                    "DesiredCapacity": "1",
                    "VPCZoneIdentifier": [subnet_id],
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                },
            },
            "ScalingPolicy": {
                "Type": "AWS::AutoScaling::ScalingPolicy",
                "Properties": {
                    "AutoScalingGroupName": {"Ref": "ASG"},
                    "PolicyType": "SimpleScaling",
                    "AdjustmentType": "ChangeInCapacity",
                    "ScalingAdjustment": 1,
                    "Cooldown": "0",
                },
            },
        },
        "Outputs": {
            "AsgName": {"Value": {"Ref": "ASG"}},
            "PolicyName": {"Value": {"Fn::GetAtt": ["ScalingPolicy", "PolicyName"]}},
        },
    }

    def _cleanup_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))

    ctx.on_cleanup(_cleanup_stack)

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 900.0) / 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(
                f"stack {stack_name} reaching CREATE_COMPLETE: the run budget ended first; "
                "not graded"
            ) from exc
        raise
    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}
    policy_name = outputs["PolicyName"]

    # Baseline: the group must actually reach its initial DesiredCapacity=1 before we execute the policy.
    _poll_until_instance_count(ctx, asg_name, expected=1, timeout_s=480)

    before = time.time()
    asgc.execute_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name, HonorCooldown=False)

    # ExecutePolicy (ChangeInCapacity +1) must launch a second real, InService instance.
    _poll_until_instance_count(ctx, asg_name, expected=2, timeout_s=480)
    group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    assert group["DesiredCapacity"] == 2, (
        f"expected DesiredCapacity=2 on {asg_name} after ExecutePolicy, observed {group['DesiredCapacity']}"
    )

    # And it must leave a recorded, Successful scaling activity attributable to the policy execution.
    activity = _poll_for_successful_activity_after(
        ctx, asg_name, after_epoch=before, policy_name=policy_name, timeout_s=180
    )
    assert activity["StatusCode"] == "Successful", (
        f"expected a Successful scaling activity for {asg_name}, observed {activity['StatusCode']!r}: {activity}"
    )
    cause = activity.get("Cause", "")
    assert policy_name in cause or "policy" in cause.lower(), (
        f"expected the scaling activity Cause to attribute the change to policy {policy_name!r}, observed {cause!r}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_instance_count(ctx, asg_name, expected, timeout_s=480.0, interval_s=1.5):
    asgc = ctx.client("autoscaling")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        last = groups[0]["Instances"] if groups else []
        in_service = [i for i in last if i["LifecycleState"] == "InService"]
        if len(in_service) >= expected:
            return in_service
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{expected} InService instances in {asg_name}: the run budget ended "
                           "first; not graded")
    raise AssertionError(
        f"expected {expected} InService instances in {asg_name}, observed {len(last)} after {timeout_s}s: {last}"
    )


def _poll_for_successful_activity_after(ctx, asg_name, after_epoch, policy_name, timeout_s=180.0, interval_s=1.5):
    """The Successful activity since ``after_epoch`` whose Cause attributes it to a policy."""
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    candidates = []
    while time.monotonic() < deadline:
        activities = asgc.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"]
        candidates = [
            a for a in activities
            if a["StartTime"].timestamp() >= after_epoch - 5 and a["StatusCode"] == "Successful"
        ]
        for activity in candidates:
            cause = activity.get("Cause", "")
            if policy_name in cause or "policy" in cause.lower():
                return activity
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"a policy-attributed Successful scaling activity for {asg_name}: the "
                           "run budget ended first; not graded")
    if candidates:
        raise AssertionError(
            f"expected the scaling activity Cause to attribute the change to policy {policy_name!r}, "
            f"observed {[a.get('Cause', '') for a in candidates]!r}"
        )
    raise AssertionError(f"no Successful scaling activity recorded for {asg_name} after ExecutePolicy")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
