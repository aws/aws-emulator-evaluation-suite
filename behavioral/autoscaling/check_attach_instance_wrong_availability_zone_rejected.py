"""attach-instance-wrong-availability-zone-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-instance-wrong-availability-zone-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachInstances rejects an instance whose Availability Zone is not one of the
    target ASG's configured AvailabilityZones -- the instance is never added to the
    group -- while attaching a same-AZ instance in the same call shape succeeds."""
    ctx.client("ec2")
    asgc = ctx.client("autoscaling")

    zones = _available_azs(ctx)
    if len(zones) < 2:

        raise AssertionError(
            f"region {ctx.region} only exposes {len(zones)} availability zone(s); "
            "this check needs at least 2 to construct an AZ mismatch"
        )
    az_in, az_out = zones[0], zones[1]

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    lt_id = _create_launch_template(ctx)
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        AvailabilityZones=[az_in],
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az_in]),
    )
    ctx.on_cleanup(lambda: _delete_asg_and_wait(ctx, asg_name))

    ami_id = _latest_al2_ami(ctx)
    outside_instance_id = _launch_and_wait_running(ctx, ami_id, az_out)
    inside_instance_id = _launch_and_wait_running(ctx, ami_id, az_in)

    code, message = _client_error(
        lambda: asgc.attach_instances(AutoScalingGroupName=asg_name, InstanceIds=[outside_instance_id])
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == (
        f"The list of availability zones [{az_in}] for the group {asg_name} does not contain "
        f"the zone occupied by the instance {outside_instance_id} [{az_out}]"
    ), f"expected the exact refusal message, got {message!r}"

    # (b) effect absent: the mismatched-AZ instance was never attached.
    group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    attached_ids = [i["InstanceId"] for i in group.get("Instances", [])]
    assert outside_instance_id not in attached_ids, f"instance from the wrong AZ got attached: {attached_ids}"
    assert attached_ids == [], f"expected no instances attached yet, found: {attached_ids}"

    # (c) positive control: the same call shape, with a same-AZ instance, succeeds.
    asgc.attach_instances(AutoScalingGroupName=asg_name, InstanceIds=[inside_instance_id])
    attached_ids = _poll_attached(ctx, asg_name, timeout_s=90)
    assert inside_instance_id in attached_ids, f"same-AZ AttachInstances did not take effect: {attached_ids}"


# ===== helpers =====
def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _available_azs(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return [z["ZoneName"] for z in zones]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


def _launch_and_wait_running(ctx, ami_id: str, az: str, timeout_s: float = 180.0) -> str:
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-behav-attach-az-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        Placement={"AvailabilityZone": az},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": marker}]}],
        SubnetId=_network_subnet_in(ctx, az),
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                # eventual consistency: the instance can be briefly unreadable
                # right after RunInstances returns.
                time.sleep(5)
                continue
            raise
        if desc["State"]["Name"] == "running":
            return instance_id
        time.sleep(5)
    raise AssertionError(f"instance {instance_id} never reached running state")


def _poll_attached(ctx, asg_name: str, timeout_s: float = 90.0):
    asgc = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    ids: list[str] = []
    while time.monotonic() < deadline:
        group = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        ids = [i["InstanceId"] for i in group.get("Instances", [])]
        if ids:
            return ids
        time.sleep(5)
    return ids


def _delete_asg_and_wait(ctx, asg_name: str, timeout_s: float = 300.0) -> None:
    """Force-delete the group and wait until it is gone; only "not found" counts as gone."""
    asgc = ctx.client("autoscaling")
    try:
        asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as e:
        err = e.response["Error"]
        if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return
        time.sleep(2)
    raise AssertionError(f"group {asg_name} still present {timeout_s}s after ForceDelete")


def _network_subnet_in(ctx, zone) -> str:
    """The shared network's subnet in `zone`."""
    by_zone = ctx.network().subnets
    if zone not in by_zone:
        raise AssertionError(f"the run's shared network has no subnet in {zone}")
    return by_zone[zone]


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
