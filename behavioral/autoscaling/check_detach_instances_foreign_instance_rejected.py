"""detach-instances-foreign-instance-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "detach-instances-foreign-instance-rejected"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachInstances rejects an instance id that is not a member of the named Auto Scaling
    group, leaving the group's membership unchanged, while detaching a real member succeeds."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    members = _poll_until(
        lambda: _group_instances(asg, group_name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    real_id = members[0]["InstanceId"]

    foreign_id = "i-0123456789abcdef0"
    code, message = _error(
        lambda: asg.detach_instances(
            AutoScalingGroupName=group_name, InstanceIds=[foreign_id], ShouldDecrementDesiredCapacity=False
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"The instance {foreign_id} is not part of Auto Scaling group {group_name}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = _group_instances(asg, group_name)
    assert [i["InstanceId"] for i in unchanged] == [real_id], (
        f"a rejected DetachInstances on {foreign_id!r} must not alter membership, "
        f"expected only {real_id!r}, got {[i['InstanceId'] for i in unchanged]!r}"
    )

    asg.detach_instances(
        AutoScalingGroupName=group_name, InstanceIds=[real_id], ShouldDecrementDesiredCapacity=True
    )
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[real_id]))

    def _detached() -> bool:
        group = _describe_group(asg, group_name)
        return group["DesiredCapacity"] == 0 and all(i["InstanceId"] != real_id for i in group["Instances"])

    assert _poll_until_bool(_detached, timeout_s=120.0, interval_s=5.0), (
        f"expected {real_id!r} to leave the group and DesiredCapacity to reach 0 within 120s"
    )
    final_group = _describe_group(asg, group_name)
    assert final_group["DesiredCapacity"] == 0, f"expected DesiredCapacity 0, got {final_group['DesiredCapacity']}"
    assert all(i["InstanceId"] != real_id for i in final_group["Instances"]), (
        f"detached instance {real_id} is still listed: {[i['InstanceId'] for i in final_group['Instances']]!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _describe_group(asg, name: str) -> dict:
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    assert len(groups) == 1, f"expected exactly one group named {name!r}, got {len(groups)}"
    return groups[0]


def _group_instances(asg, name: str) -> list:
    return _describe_group(asg, name)["Instances"]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


def _poll_until_bool(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
