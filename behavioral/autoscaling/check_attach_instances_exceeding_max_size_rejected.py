"""attach-instances-exceeding-max-size-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-instances-exceeding-max-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachInstances that would push a group's instance count above MaxSize
    is rejected -- a wrong-state boundary specific to the attach path, rather
    than SetDesiredCapacity."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _get_amazon_linux_ami(ctx)
    subnet_id, _az = _get_default_subnet(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    # MaxSize=0: the group is not allowed to hold any instances at all.
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    # NOTE: registered further below, AFTER the instance-terminate cleanup, so
    # that on teardown the ASG (which owns the instance once attached, and
    # will terminate it via ForceDelete) is cleaned up BEFORE the defensive
    # direct-terminate call below -- otherwise terminating the instance out
    # from under a live ASG would make it launch a replacement.

    name_tag = ctx.unique_name("sim2real-behav-instance-")
    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # Break exactly one thing: attach 1 instance to a group whose MaxSize is 0.
    code, message = _client_error(
        lambda: autoscaling.attach_instances(
            InstanceIds=[instance_id], AutoScalingGroupName=asg_name
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == (
        f"AutoScalingGroup {asg_name} has min-size=0, max-size=0, and desired-size=0. "
        "To attach 1 instance, please update the AutoScalingGroup sizes appropriately."
    ), f"expected the exact refusal message, got {message!r}"

    # Effect absent: the group still has no instances.
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["Instances"] == [], "no instance should have been attached"

    # Positive control: raise MaxSize to 1, then the identical attach succeeds.
    autoscaling.update_auto_scaling_group(AutoScalingGroupName=asg_name, MaxSize=1)
    autoscaling.attach_instances(InstanceIds=[instance_id], AutoScalingGroupName=asg_name)

    attached = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]["Instances"],
        lambda instances: any(i["InstanceId"] == instance_id for i in instances),
        timeout_s=60,
    )
    assert any(i["InstanceId"] == instance_id for i in attached), (
        f"expected {instance_id!r} to be attached after MaxSize was raised to 1, "
        f"got instances {[i['InstanceId'] for i in attached]!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_amazon_linux_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _get_default_subnet(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError("no network subnet available in this account/region")
    subnet = subnets[0]
    return subnet["SubnetId"], subnet["AvailabilityZone"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
