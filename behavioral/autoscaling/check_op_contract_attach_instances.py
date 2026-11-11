"""op-contract-attachInstances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-attachInstances"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachInstances increases DesiredCapacity and moves the instance InService;
    attaching past MaxSize fails and leaves the instance un-attached; raising MaxSize
    then permits the identical call to succeed."""
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    # Registered AFTER the instance-terminate cleanup below so that, under the
    # engine's LIFO teardown, the ASG (which owns any attached instance and will
    # terminate it via ForceDelete) is cleaned up BEFORE the defensive direct-terminate
    # call -- otherwise terminating an instance out from under a live ASG makes it
    # launch a replacement mid-teardown.

    tag = ctx.unique_name("sim2real-behav-inst-")
    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=2,
        MaxCount=2,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": tag}]}
        ],
    )
    instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))
    ctx.on_cleanup(_delete_group)

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    instance1, instance2 = instance_ids[0], instance_ids[1]

    # --- success path: attach instance1, fills the group to MaxSize=1 ---
    asg.attach_instances(AutoScalingGroupName=group_name, InstanceIds=[instance1])

    def _probe1():
        return asg.describe_auto_scaling_instances(InstanceIds=[instance1])[
            "AutoScalingInstances"
        ]

    attached = _poll_until(
        _probe1,
        lambda insts: len(insts) == 1 and insts[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert attached[0]["AutoScalingGroupName"] == group_name, (
        f"expected instance1 to be a member of {group_name}, got {attached[0]!r}"
    )

    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ]
    assert groups[0]["DesiredCapacity"] == 1, (
        f"expected DesiredCapacity == 1 after attaching instance1, got {groups[0]['DesiredCapacity']!r}"
    )

    # --- error boundary: attaching a second instance would exceed MaxSize=1 ---
    code, message = _error(
        lambda: asg.attach_instances(AutoScalingGroupName=group_name, InstanceIds=[instance2])
    )
    assert code == "ValidationError", f"expected ValidationError for exceeding MaxSize, got {code}"
    expected_message = (
        f"AutoScalingGroup {group_name} has min-size=0, max-size=1, and desired-size=1. "
        "To attach 1 instance, please update the AutoScalingGroup sizes appropriately."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_unattached = asg.describe_auto_scaling_instances(InstanceIds=[instance2])[
        "AutoScalingInstances"
    ]
    assert still_unattached == [], "instance2 must not have been attached after the rejected call"

    # --- restore: raising MaxSize permits the identical call to succeed ---
    asg.update_auto_scaling_group(AutoScalingGroupName=group_name, MaxSize=2)
    asg.attach_instances(AutoScalingGroupName=group_name, InstanceIds=[instance2])

    def _probe2():
        return asg.describe_auto_scaling_instances(InstanceIds=[instance2])[
            "AutoScalingInstances"
        ]

    attached2 = _poll_until(
        _probe2,
        lambda insts: len(insts) == 1 and insts[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert attached2[0]["AutoScalingGroupName"] == group_name, (
        f"expected instance2 to join {group_name} after raising MaxSize, got {attached2[0]!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, so a target
    accepting a call AWS refuses is reported as such, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
