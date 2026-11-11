"""deploy-launch-template-asg-instance-launch."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-launch-template-asg-instance-launch"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ASG on a launch template launches a real EC2 instance whose InstanceType and
    instance tags match the template, not merely a group reporting DesiredCapacity 1."""
    ec2 = ctx.client("ec2")
    asgc = ctx.client("autoscaling")

    ami_id = _latest_al2_ami(ctx)
    subnet_id = _default_vpc_subnet(ctx, "t3.micro")
    marker = ctx.unique_name("sim2real-behav-marker-")
    lt_name = ctx.unique_name("sim2real-behav-lt-")

    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": [{"Key": "sim2real-marker", "Value": marker}]}
            ],
        },
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-marker", "Value": marker}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=1,
        MaxSize=1,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real-marker", "Value": marker, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _delete_asg_and_wait(ctx, asg_name))

    instance_id = _poll_for_instance(ctx, asg_name, timeout_s=180)
    assert instance_id, "ASG never reported a launched instance"

    instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert instance["InstanceType"] == "t3.micro", instance["InstanceType"]
    instance_tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    assert instance_tags.get("sim2real-marker") == marker, instance_tags


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


def _default_vpc_subnet(ctx, instance_type: str) -> str:
    """A subnet in the run's shared network, in an AZ that actually offers `instance_type`.

    Deriving this explicitly (rather than passing AvailabilityZones to
    create_auto_scaling_group and letting the service resolve a default-VPC subnet on our
    behalf) means a fresh account with no shared network fails loudly here instead of via an
    opaque ASG-side error, and we never launch into an AZ that can't serve the instance type.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "no shared network VPC in this account/region to launch instances into"
    vpc_id = vpcs[0]["VpcId"]

    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}, {"Name": "location", "Values": ctx.network().availability_zones}],
        )["InstanceTypeOfferings"]
    }
    subnets = []
    for page in ec2.get_paginator("describe_subnets").paginate(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ):
        subnets += page["Subnets"]
    usable = [
        s
        for s in sorted(subnets, key=lambda s: s["SubnetId"])
        if s["AvailabilityZone"] in offered and s.get("AvailableIpAddressCount", 0) > 0
    ]
    assert usable, f"no network subnet in an AZ offering {instance_type!r}; offered={sorted(offered)!r}"
    return usable[0]["SubnetId"]


def _poll_for_instance(ctx, asg_name: str, timeout_s: float = 180.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        instances = group.get("Instances", [])
        if instances:
            return instances[0]["InstanceId"]
        time.sleep(5)
    return None


def _delete_asg_and_wait(ctx, asg_name: str, timeout_s: float = 300.0) -> None:
    asgc = ctx.client("autoscaling")
    try:
        asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return
        time.sleep(2)
    raise RuntimeError(f"group {asg_name} still listed {timeout_s}s after its ForceDelete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
