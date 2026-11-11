"""describe-scaling-process-types-static-list."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-scaling-process-types-static-list"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeScalingProcessTypes returns the fixed set of process names, and those
    exact names are the ones SuspendProcesses/ResumeProcesses accept and record on the
    group's SuspendedProcesses list."""
    autoscaling = ctx.client("autoscaling")

    resp = autoscaling.describe_scaling_process_types()
    names = {p["ProcessName"] for p in resp["Processes"]}

    expected = {
        "Launch",
        "Terminate",
        "AddToLoadBalancer",
        "AlarmNotification",
        "AZRebalance",
        "HealthCheck",
        "ReplaceUnhealthy",
        "ScheduledActions",
        "InstanceRefresh",
    }
    assert names == expected, f"unexpected scaling process types: {names}"

    asg_name = _create_empty_asg(ctx)

    # Suspend two of the exact process names returned above and confirm the group
    # records exactly those two (and no others) as suspended.
    to_suspend = ["AlarmNotification", "AZRebalance"]
    autoscaling.suspend_processes(AutoScalingGroupName=asg_name, ScalingProcesses=to_suspend)

    described = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    group = described["AutoScalingGroups"][0]
    suspended = {p["ProcessName"] for p in group["SuspendedProcesses"]}
    assert suspended == set(to_suspend), f"expected {to_suspend} suspended, got {suspended}"

    # Resuming all processes clears SuspendedProcesses entirely.
    autoscaling.resume_processes(AutoScalingGroupName=asg_name)
    described2 = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    group2 = described2["AutoScalingGroups"][0]
    assert group2["SuspendedProcesses"] == [], group2["SuspendedProcesses"]


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


def _create_empty_asg(ctx) -> str:
    """Creates a MinSize=0/MaxSize=0/DesiredCapacity=0 group so no instances launch."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_al2_ami(ctx)
    subnet_id = _get_default_subnet_id(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    _wait_for_group_status_settled(ctx, asg_name)
    return asg_name


def _wait_for_group_status_settled(ctx, asg_name: str, timeout_s: float = 60.0) -> None:
    autoscaling = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        groups = described["AutoScalingGroups"]
        if groups and groups[0].get("AutoScalingGroupName") == asg_name:
            return
        time.sleep(2)
    raise AssertionError(f"group {asg_name} never became describable")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
