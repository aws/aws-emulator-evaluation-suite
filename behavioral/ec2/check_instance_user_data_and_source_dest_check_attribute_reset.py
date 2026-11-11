"""instance-user-data-and-source-dest-check-attribute-reset."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-user-data-and-source-dest-check-attribute-reset"
GROUP = 'instance-lifecycle'
SERVICES = ['ec2']

ERR_INVALID_PARAM = 'InvalidParameterValue'
USER_DATA = b"#!/bin/bash\necho sim2real-user-data\n"

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _test_ami_id(ec2):
    """Return the newest x86_64 HVM EBS ImageId for RunInstances."""
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
    raise AssertionError("could not discover a usable test AMI")


def _get_default_subnet(ec2, *, ctx):
    try:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
    except ClientError as exc:
        raise AssertionError(f"could not list network subnets: {exc}")
    if not subnets:
        raise AssertionError("account has no network subnet for AZ-pinned launches")
    return subnets[0]["SubnetId"]


def _wait_instance_state(ec2, instance_id, state, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        except ClientError as exc:
            if _code(exc) == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        last = resv[0]["Instances"][0]["State"]["Name"] if resv and resv[0].get("Instances") else "__none__"
        if last == state:
            return
        time.sleep(3)
    raise AssertionError(f"instance {instance_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _attr(ec2, instance_id, attribute):
    return ec2.describe_instance_attribute(InstanceId=instance_id, Attribute=attribute)


def _user_data_bytes(ec2, instance_id):
    """Return the decoded userData bytes.

    DescribeInstanceAttribute returns it base64-encoded and botocore does not decode it."""
    value = _attr(ec2, instance_id, "userData").get("UserData", {}).get("Value")
    return None if value is None else base64.b64decode(value)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UserData set on a stopped instance round-trips byte-for-byte and survives a restart,
    sourceDestCheck round-trips as a boolean and resets to its default, and resetting a
    non-resettable attribute is rejected without side effects.
    """
    ec2 = ctx.client("ec2")
    subnet_id = _get_default_subnet(ec2, ctx=ctx)
    instance_id = ec2.run_instances(
        ImageId=_test_ami_id(ec2), InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    # a launch without UserData exposes an empty userData attribute, not a missing one
    launched = _attr(ec2, instance_id, "userData")
    assert launched["InstanceId"] == instance_id, (
        f"DescribeInstanceAttribute must echo the instance id, got {launched.get('InstanceId')!r}"
    )
    assert not _user_data_bytes(ec2, instance_id), (
        f"an instance launched without UserData must report none, got {_user_data_bytes(ec2, instance_id)!r}"
    )

    # sourceDestCheck defaults to true and is a real boolean, not a string
    src = _attr(ec2, instance_id, "sourceDestCheck")["SourceDestCheck"]["Value"]
    assert src is True, f"sourceDestCheck must default to boolean True, got {src!r} ({type(src).__name__})"

    # userData is writable only while the instance is stopped
    ec2.stop_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "stopped")
    ec2.modify_instance_attribute(InstanceId=instance_id, UserData={"Value": USER_DATA})
    got = _user_data_bytes(ec2, instance_id)
    assert got == USER_DATA, f"userData must round-trip byte-for-byte; wrote {USER_DATA!r}, read {got!r}"

    ec2.modify_instance_attribute(InstanceId=instance_id, SourceDestCheck={"Value": False})
    src = _attr(ec2, instance_id, "sourceDestCheck")["SourceDestCheck"]["Value"]
    assert src is False, f"expected sourceDestCheck False after the write, got {src!r}"
    ec2.reset_instance_attribute(InstanceId=instance_id, Attribute="sourceDestCheck")
    src = _attr(ec2, instance_id, "sourceDestCheck")["SourceDestCheck"]["Value"]
    assert src is True, f"ResetInstanceAttribute must restore sourceDestCheck to True, got {src!r}"

    # only kernel, ramdisk and sourceDestCheck are resettable
    try:
        ec2.reset_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} resetting the non-resettable 'instanceType', got {_code(exc)}"
        )
        assert exc.response["Error"]["Message"] == (
            "Value (instanceType) for parameter attribute is invalid. Unknown attribute."
        ), exc.response["Error"]
    else:
        raise AssertionError(
            "ResetInstanceAttribute(instanceType) must be rejected — only kernel, ramdisk and "
            "sourceDestCheck are resettable — it succeeded"
        )
    assert _user_data_bytes(ec2, instance_id) == USER_DATA, (
        "a rejected ResetInstanceAttribute must not clear userData"
    )
    assert _attr(ec2, instance_id, "instanceType")["InstanceType"]["Value"] == "t3.micro", (
        "a rejected ResetInstanceAttribute must not change the instance type"
    )

    ec2.start_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "running")
    survived = _user_data_bytes(ec2, instance_id)
    assert survived == USER_DATA, f"userData must survive a stop/start cycle, read {survived!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
