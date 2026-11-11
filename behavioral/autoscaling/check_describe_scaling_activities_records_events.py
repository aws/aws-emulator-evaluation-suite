"""describe-scaling-activities-records-events."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-scaling-activities-records-events"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SetDesiredCapacity call that changes a group's capacity produces an Activity
    record retrievable via DescribeScalingActivities, and that activity's StatusCode
    progresses from an in-flight code to the terminal 'Successful' with Progress=100."""
    autoscaling = ctx.client("autoscaling")

    ami = _get_al2_ami(ctx)
    subnet_id = _get_default_subnet_id(ctx)

    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    before_ids = {a["ActivityId"] for a in _activities(ctx, asg_name)}

    autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    new_activity = _poll_until(
        lambda: [a for a in _activities(ctx, asg_name) if a["ActivityId"] not in before_ids],
        lambda acts: len(acts) >= 1,
        timeout_s=60.0,
        interval_s=3.0,
    )[0]

    assert new_activity["AutoScalingGroupName"] == asg_name, (
        f"expected {asg_name!r}, got {new_activity['AutoScalingGroupName']!r}"
    )
    assert "desired capacity" in new_activity["Cause"].lower(), new_activity["Cause"]

    terminal = _poll_until(
        lambda: autoscaling.describe_scaling_activities(
            AutoScalingGroupName=asg_name, ActivityIds=[new_activity["ActivityId"]]
        )["Activities"][0],
        lambda act: act["StatusCode"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    assert terminal["StatusCode"] == "Successful", terminal
    assert terminal["Progress"] == 100, terminal["Progress"]


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")
    return param["Parameter"]["Value"]


def _get_default_subnet_id(ctx) -> str:

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no default-for-az subnet available in this account/region")
    return subnets[0]["SubnetId"]


def _activities(ctx, asg_name: str) -> list:
    autoscaling = ctx.client("autoscaling")
    return autoscaling.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
