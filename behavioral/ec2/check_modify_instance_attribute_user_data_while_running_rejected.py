"""modify-instance-attribute-user-data-while-running-rejected."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-attribute-user-data-while-running-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

USER_DATA = b"#!/bin/bash\necho sim2real-user-data\n"
_GONE_CODES = ("InvalidInstanceID.NotFound",)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceAttribute(UserData) on a running instance is rejected with
    IncorrectInstanceState, userData stays empty, and the identical call succeeds once the
    instance is stopped.
    """
    ec2 = ctx.client("ec2")
    subnet_id = _get_default_subnet(ec2, ctx=ctx)
    instance_id = ec2.run_instances(
        ImageId=_test_ami_id(ec2), InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    _wait_instance_state(ec2, instance_id, "running")

    assert not _user_data_bytes(ec2, instance_id), (
        f"an instance launched without UserData must report none, got "
        f"{_user_data_bytes(ec2, instance_id)!r}"
    )

    _NOT_STOPPED = ("IncorrectInstanceState", f"The instance '{instance_id}' is not in the 'stopped' state.")
    expect_error(
        lambda: ec2.modify_instance_attribute(InstanceId=instance_id, UserData={"Value": USER_DATA}),
        *_NOT_STOPPED,
    )

    # Effect-absent: an independent read confirms userData stayed empty while running.
    assert not _user_data_bytes(ec2, instance_id), (
        f"a rejected ModifyInstanceAttribute(UserData) must not change userData while running, "
        f"got {_user_data_bytes(ec2, instance_id)!r}"
    )

    # Positive control: the identical write succeeds once the instance is stopped.
    ec2.stop_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "stopped")
    ec2.modify_instance_attribute(InstanceId=instance_id, UserData={"Value": USER_DATA})
    got = _user_data_bytes(ec2, instance_id)
    assert got == USER_DATA, f"userData must round-trip byte-for-byte once stopped; wrote {USER_DATA!r}, read {got!r}"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _terminate(ec2, instance_id):
    """Terminate the instance and wait until it reports 'terminated'."""
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) not in _GONE_CODES:
            raise
        return
    _wait_instance_state(ec2, instance_id, "terminated", timeout_s=600)


def _test_ami_id(ec2):
    """The newest Amazon-owned Amazon Linux 2023 x86_64 HVM EBS image."""
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 x86_64 AMI visible in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
