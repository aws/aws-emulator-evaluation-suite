"""ec2-userdata-run-instances-and-launch-template-no-double-encoding."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-userdata-run-instances-and-launch-template-no-double-encoding"
GROUP = "userdata-encoding"
SERVICES = ["ec2"]

RAW_TEMPLATE = b"#!/bin/bash\necho sim2real-template\n"
ENCODED_TEMPLATE = base64.b64encode(RAW_TEMPLATE).decode()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Pre-encoded base64 UserData stored by CreateLaunchTemplate reads back unchanged, and an
    instance launched from the template reports the same string via DescribeInstanceAttribute.
    """
    ec2 = ctx.client("ec2")
    ami_id = _test_ami_id(ec2)
    subnet_id = _own_subnet(ctx, ec2)

    # Direct RunInstances is not used: botocore always base64-encodes its UserData client-side,
    # while CreateLaunchTemplate takes the string as-is, isolating server-side behaviour.
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=ctx.unique_name("sim2real-behav-udlt-"),
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "UserData": ENCODED_TEMPLATE,
        },
        TagSpecifications=[_tag_spec(ctx, "launch-template", "udlt")],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    stored = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id, Versions=["$Latest"])[
        "LaunchTemplateVersions"
    ][0]["LaunchTemplateData"]["UserData"]
    assert stored == ENCODED_TEMPLATE, (
        f"CreateLaunchTemplate stored UserData as {stored!r}, expected the exact pre-encoded "
        f"string {ENCODED_TEMPLATE!r} with no additional base64 layer applied by the service"
    )

    instance_id = ec2.run_instances(
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        TagSpecifications=[_tag_spec(ctx, "instance", "ud-template")],
    )["Instances"][0]["InstanceId"]
    terminated = {"value": False}
    ctx.on_cleanup(lambda: None if terminated["value"] else _terminate(ec2, instance_id))

    got = _wait_user_data(ec2, instance_id)
    assert got == ENCODED_TEMPLATE, (
        f"launch-template RunInstances UserData round-tripped to {got!r} via "
        f"DescribeInstanceAttribute, expected the exact pre-encoded string {ENCODED_TEMPLATE!r} "
        "with no additional base64 layer applied by the service"
    )

    _terminate(ec2, instance_id)
    terminated["value"] = True


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{prefix}-")}],
    }


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except ClientError:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable x86_64 HVM EBS AMI")


def _own_subnet(ctx, ec2):
    """A subnet in a VPC this check creates, in an AZ offering t3.micro, torn down after the
    instance with the subnet delete retried while its interface drains."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers t3.micro; offerings were {sorted(offered)!r}"
    vpc = ec2.create_vpc(CidrBlock="10.76.0.0/16",
                         TagSpecifications=[_tag_spec(ctx, "vpc", "ud-vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.76.1.0/24", AvailabilityZone=usable[0],
                               TagSpecifications=[_tag_spec(ctx, "subnet", "ud-subnet")])[
        "Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _delete_retrying(call, *, budget_s: float = 420.0) -> None:
    """One teardown delete, retried while a terminated instance's interface drains; raises otherwise."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            call()
            return
        except ClientError as exc:
            code = _code(exc)
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(10)


def _wait_user_data(ec2, instance_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
            value = attr.get("UserData", {}).get("Value")
            if value is not None:
                return value
            last_exc = AssertionError(f"userData attribute present but empty for {instance_id}")
        except ClientError as exc:
            if _code(exc) != "InvalidInstanceID.NotFound":
                raise
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(f"UserData for {instance_id} never became readable within {timeout_s}s: {last_exc!r}")


def _terminate(ec2, instance_id):
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
