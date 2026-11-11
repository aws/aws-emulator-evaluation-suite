"""op-contract-enterStandby."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-enterStandby"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnterStandby moves an InService instance to Standby and decrements
    DesiredCapacity when allowed; it is rejected when decrementing would push
    DesiredCapacity below MinSize, and the instance stays InService."""
    asg = ctx.client("autoscaling")

    # --- success path: MinSize=0 so decrementing to 0 is allowed ---
    group_a, instance_a = _create_asg_with_instance(ctx, desired=1, min_size=0, max_size=2)
    asg.enter_standby(
        AutoScalingGroupName=group_a,
        InstanceIds=[instance_a],
        ShouldDecrementDesiredCapacity=True,
    )

    def _probe_a():
        return asg.describe_auto_scaling_instances(InstanceIds=[instance_a])[
            "AutoScalingInstances"
        ][0]["LifecycleState"]

    final_state = _poll_until(_probe_a, lambda s: s == "Standby", timeout_s=120.0, interval_s=5.0)
    assert final_state == "Standby"

    group_a_desc = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_a])[
        "AutoScalingGroups"
    ][0]
    assert group_a_desc["DesiredCapacity"] == 0

    # --- error boundary: MinSize=1, decrementing would go below MinSize ---
    group_b, instance_b = _create_asg_with_instance(ctx, desired=1, min_size=1, max_size=1)
    code, message = _error(
        lambda: asg.enter_standby(
            AutoScalingGroupName=group_b,
            InstanceIds=[instance_b],
            ShouldDecrementDesiredCapacity=True,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = (
        f"AutoScalingGroup {group_b} has min-size=1, max-size=1, and desired-size=1. "
        "To place into standby 1 instance, please update the AutoScalingGroup sizes appropriately."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    state_b = asg.describe_auto_scaling_instances(InstanceIds=[instance_b])[
        "AutoScalingInstances"
    ][0]["LifecycleState"]
    assert state_b == "InService", "instance must remain InService after the rejected call"


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]

    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in shared network")
    return subnets[0]["SubnetId"], vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg_with_instance(ctx, desired=1, min_size=0, max_size=2):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckType="EC2",
        HealthCheckGracePeriod=30,
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_delete_group)

    def _probe():
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ]
        return groups[0]["Instances"] if groups else []

    instances = _poll_until(
        _probe,
        lambda insts: len([i for i in insts if i["LifecycleState"] == "InService"]) >= desired,
        timeout_s=420.0,
        interval_s=10.0,
    )
    in_service = [i for i in instances if i["LifecycleState"] == "InService"]
    return group_name, (in_service[0]["InstanceId"] if in_service else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
