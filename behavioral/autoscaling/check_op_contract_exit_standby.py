"""op-contract-exit-standby."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-exit-standby"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExitStandby moves a Standby instance back InService and increments DesiredCapacity;
    a fabricated instance ID that never belonged to the group is rejected without effect."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _own_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-exitstandby-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=2, desired=1)

    instances = _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    instance_id = instances[0]["InstanceId"]

    before = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    desired_before = before["DesiredCapacity"]
    assert desired_before == 1, f"expected DesiredCapacity 1 after group settles, got {desired_before}"

    autoscaling.enter_standby(
        AutoScalingGroupName=name, InstanceIds=[instance_id], ShouldDecrementDesiredCapacity=False
    )
    _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: any(i["InstanceId"] == instance_id and i["LifecycleState"] == "Standby" for i in ins),
        timeout_s=120.0,
        interval_s=5.0,
    )

    resp = autoscaling.exit_standby(AutoScalingGroupName=name, InstanceIds=[instance_id])
    activities = resp["Activities"]
    assert len(activities) == 1, f"expected exactly 1 activity from ExitStandby, got {len(activities)}"
    assert instance_id in activities[0]["Description"], (
        f"expected {instance_id!r} named in the activity description, got {activities[0]['Description']!r}"
    )
    assert "Standby" in activities[0]["Description"], (
        f"expected 'Standby' referenced in the activity description, got {activities[0]['Description']!r}"
    )

    _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: any(i["InstanceId"] == instance_id and i["LifecycleState"] == "InService" for i in ins),
        timeout_s=180.0,
        interval_s=10.0,
    )

    after = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    # ExitStandby increments DesiredCapacity by exactly 1 per the documented contract, regardless
    # of whether the matching EnterStandby decremented it.
    assert after["DesiredCapacity"] == desired_before + 1, (
        f"expected DesiredCapacity {desired_before + 1} after ExitStandby, got {after['DesiredCapacity']}"
    )

    # Error boundary: an instance ID that was never part of this group is rejected, and no
    # scaling activity or capacity mutation results from the rejected call.
    fake_instance_id = "i-00000000000000001"
    code, message = _error(
        lambda: autoscaling.exit_standby(AutoScalingGroupName=name, InstanceIds=[fake_instance_id])
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"The instance {fake_instance_id} is not part of Auto Scaling group {name}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    unchanged = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert unchanged["DesiredCapacity"] == after["DesiredCapacity"], (
        f"a rejected ExitStandby call must not change DesiredCapacity: "
        f"expected {after['DesiredCapacity']}, got {unchanged['DesiredCapacity']}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises rather than
    being reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _resolve_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _delete_with_retry(fn, *, not_found_code: str, timeout_s: float, interval_s: float = 3.0) -> None:
    """Retry a delete that fails with DependencyViolation while an ASG instance this check just
    force-deleted is still detaching its ENI in the background -- the ASG delete call returns long
    before that termination completes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == not_found_code:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _own_subnet(ctx) -> str:
    """Subnet in a VPC this check creates and owns, rather than assuming the account already has
    a default VPC -- a freshly provisioned account may not."""
    ec2 = ctx.client("ec2")
    cidr = "10.202.0.0/24"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: ec2.delete_vpc(VpcId=vpc_id), not_found_code="InvalidVpcID.NotFound", timeout_s=120.0
        )
    )
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=3.0,
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: ec2.delete_subnet(SubnetId=subnet_id),
            not_found_code="InvalidSubnetID.NotFound",
            timeout_s=360.0,
            interval_s=10.0,
        )
    )
    return subnet_id


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, subnet_id: str, min_size: int, max_size: int, desired: int) -> None:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))


def _group_instances(ctx, name: str) -> list[dict[str, Any]]:
    autoscaling = ctx.client("autoscaling")
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0]["Instances"] if groups else []


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
