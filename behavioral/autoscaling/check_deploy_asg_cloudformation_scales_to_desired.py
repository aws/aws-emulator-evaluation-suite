"""deploy-asg-cloudformation-scales-to-desired."""
from __future__ import annotations

import json
import time

from botocore.exceptions import WaiterError

from behavioral_harness import tags

CHECK = "deploy-asg-cloudformation-scales-to-desired"
GROUP = "deploy"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An ASG provisioned via CloudFormation actually launches EC2-backed instances up to
    DesiredCapacity (not merely CREATE_COMPLETE), and a subsequent SetDesiredCapacity call
    launches a real second instance rather than just updating group metadata."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    ami_id = _get_al2023_ami(ctx)
    subnet_id, _vpc_id = _get_default_subnet(ctx)

    stack_name = ctx.unique_name("sim2real-behav-asgcfn-")
    asg_name = ctx.unique_name("sim2real-behav-asg-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {
                        "ImageId": ami_id,
                        "InstanceType": "t3.micro",
                        "TagSpecifications": [
                            {
                                "ResourceType": "instance",
                                "Tags": [{"Key": "sim2real", "Value": CHECK}],
                            }
                        ],
                    }
                },
            },
            "ASG": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {
                    "AutoScalingGroupName": asg_name,
                    "MinSize": "0",
                    "MaxSize": "2",
                    "DesiredCapacity": "1",
                    "VPCZoneIdentifier": [subnet_id],
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                    "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
                },
            },
        },
        "Outputs": {"AsgName": {"Value": {"Ref": "ASG"}}},
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
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    reported_asg_name = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "AsgName")
    assert reported_asg_name == asg_name, (
        f"expected stack output AsgName to echo {asg_name!r}, got {reported_asg_name!r}"
    )

    # DesiredCapacity=1 in the template must translate into one real, running instance.
    in_service = _poll_until_instance_count(ctx, asg_name, expected=1, timeout_s=480)
    assert len(in_service) == 1, f"expected 1 InService instance in {asg_name}, got {in_service}"
    instance_id = in_service[0]["InstanceId"]
    cross_check = asgc.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
    assert len(cross_check) == 1 and cross_check[0]["LifecycleState"] == "InService", (
        f"expected {instance_id} to be a single InService AutoScalingInstance, got {cross_check}"
    )
    ec2_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert ec2_state["State"]["Name"] == "running", (
        f"expected EC2 instance {instance_id} to be running, EC2 reports {ec2_state['State']['Name']!r}"
    )

    # SetDesiredCapacity must launch a second real instance, not just bump a stored counter.
    asgc.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=2, HonorCooldown=False)
    in_service_2 = _poll_until_instance_count(ctx, asg_name, expected=2, timeout_s=480)
    assert len(in_service_2) == 2, f"expected 2 InService instances in {asg_name}, got {in_service_2}"
    instance_ids_2 = {i["InstanceId"] for i in in_service_2}
    reservations = ec2.describe_instances(InstanceIds=list(instance_ids_2))["Reservations"]
    running_ids = {
        inst["InstanceId"]
        for res in reservations
        for inst in res["Instances"]
        if inst["State"]["Name"] == "running"
    }
    assert running_ids == instance_ids_2, (
        f"ASG reported InService instances {instance_ids_2} but EC2 shows only {running_ids} running"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
