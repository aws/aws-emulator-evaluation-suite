"""op-contract-update-auto-scaling-group."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-update-auto-scaling-group"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAutoScalingGroup applies the new MinSize/MaxSize/DesiredCapacity in place and a
    DesiredCapacity increase triggers a real scale-out scaling activity; a MinSize greater than
    the group's MaxSize is rejected and the group's sizing is left completely unchanged."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-updateasg-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=3, desired=0)

    before = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert before["MinSize"] == 0 and before["MaxSize"] == 3 and before["DesiredCapacity"] == 0, (
        f"freshly created group should be (min=0, max=3, desired=0), got "
        f"(min={before['MinSize']}, max={before['MaxSize']}, desired={before['DesiredCapacity']})"
    )
    assert before["Instances"] == [], f"freshly created group should have no instances, got {before['Instances']!r}"

    autoscaling.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=1, MaxSize=4, DesiredCapacity=1)

    after = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert after["MinSize"] == 1, f"expected MinSize == 1 after update, got {after['MinSize']}"
    assert after["MaxSize"] == 4, f"expected MaxSize == 4 after update, got {after['MaxSize']}"
    assert after["DesiredCapacity"] == 1, f"expected DesiredCapacity == 1 after update, got {after['DesiredCapacity']}"

    # The DesiredCapacity increase from 0 to 1 is not just bookkeeping: it triggers a real
    # scale-out activity that launches and brings up a new instance.
    _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )

    # Error boundary: MinSize (10) greater than the group's current MaxSize (4) is rejected,
    # and none of MinSize/MaxSize/DesiredCapacity change as a result of the rejected call.
    code, message = _error(lambda: autoscaling.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=10))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "Max bound, 4, must be greater than or equal to min bound, 10"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    unchanged = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert unchanged["MinSize"] == 1, f"rejected update moved MinSize to {unchanged['MinSize']}, expected it to stay 1"
    assert unchanged["MaxSize"] == 4, f"rejected update moved MaxSize to {unchanged['MaxSize']}, expected it to stay 4"
    assert unchanged["DesiredCapacity"] == 1, (
        f"rejected update moved DesiredCapacity to {unchanged['DesiredCapacity']}, expected it to stay 1"
    )

    # Recovery: the rejection must not wedge the group. The identical call shape with a valid
    # bound pair succeeds immediately afterward.
    autoscaling.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=2, MaxSize=5)
    recovered = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert recovered["MinSize"] == 2, f"group did not recover after the rejection: MinSize is {recovered['MinSize']}, expected 2"
    assert recovered["MaxSize"] == 5, f"group did not recover after the rejection: MaxSize is {recovered['MaxSize']}, expected 5"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
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


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


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
