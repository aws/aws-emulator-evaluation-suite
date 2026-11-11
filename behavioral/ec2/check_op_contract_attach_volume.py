"""op-contract-attachVolume."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-attachVolume"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachVolume mounts an EBS volume on a running instance; a device already in use is rejected,
    the rejected volume never attaches, and the identical call succeeds once the device is freed."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    vpc = ec2.create_vpc(
        CidrBlock="10.204.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_vpc(VpcId=vpc)))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.204.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_subnet(SubnetId=subnet)))

    ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")[
        "Parameter"
    ]["Value"]
    instance = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-vol-instance-")},
                    {"Key": "sim2real", "Value": "1"},
                ],
            }
        ],
    )["Instances"][0]["InstanceId"]

    def cleanup_instance():
        _cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance]))
        _cleanup(lambda: ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 300}))

    ctx.on_cleanup(cleanup_instance)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    volume_tags = [{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    volume_a = ec2.create_volume(
        Size=1, AvailabilityZone=az, VolumeType="gp3", TagSpecifications=volume_tags
    )["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_volume(VolumeId=volume_a)))
    volume_b = ec2.create_volume(
        Size=1, AvailabilityZone=az, VolumeType="gp3", TagSpecifications=volume_tags
    )["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_volume(VolumeId=volume_b)))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_a, volume_b])["Volumes"],
        lambda vols: len(vols) == 2 and all(v["State"] == "available" for v in vols),
        timeout_s=60,
        interval_s=3,
    )

    # positive control: attach volume_a to /dev/sdf and let it settle
    resp = ec2.attach_volume(VolumeId=volume_a, InstanceId=instance, Device="/dev/sdf")
    assert resp["State"] == "attaching", f"expected State=attaching from AttachVolume, got {resp['State']!r}"

    def cleanup_attach_a():
        # IncorrectState: volume_a is already detached; the poll below confirms it is available.
        _cleanup(lambda: ec2.detach_volume(VolumeId=volume_a, InstanceId=instance, Force=True), "IncorrectState")
        _cleanup(
            lambda: _poll_until(
                lambda: ec2.describe_volumes(VolumeIds=[volume_a])["Volumes"][0]["State"],
                lambda s: s == "available",
                timeout_s=60,
                interval_s=3,
            )
        )

    ctx.on_cleanup(cleanup_attach_a)

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_a])["Volumes"][0]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "attached",
        timeout_s=60,
        interval_s=3,
    )

    # break exactly one thing: a second volume for the same, now-occupied device on this instance
    code, message = _error(lambda: ec2.attach_volume(VolumeId=volume_b, InstanceId=instance, Device="/dev/sdf"))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "Invalid value '/dev/sdf' for unixDevice. Attachment point /dev/sdf is already in use", (
        f"unexpected device-in-use message: {message!r}"
    )

    # effect absent: an independent read shows the rejected volume never attached
    volume_b_after_reject = ec2.describe_volumes(VolumeIds=[volume_b])["Volumes"][0]
    assert volume_b_after_reject["State"] == "available" and not volume_b_after_reject.get("Attachments"), (
        f"a rejected AttachVolume must leave {volume_b} unattached, got {volume_b_after_reject!r}"
    )

    # restore: free the device by detaching volume_a
    ec2.detach_volume(VolumeId=volume_a, InstanceId=instance)
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_a])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )

    # the identical call now succeeds once the device is free
    resp_b = ec2.attach_volume(VolumeId=volume_b, InstanceId=instance, Device="/dev/sdf")
    assert resp_b["State"] == "attaching", f"expected State=attaching once /dev/sdf is free, got {resp_b['State']!r}"

    def cleanup_attach_b():
        # IncorrectState: volume_b is already detached; the poll below confirms it is available.
        _cleanup(lambda: ec2.detach_volume(VolumeId=volume_b, InstanceId=instance, Force=True), "IncorrectState")
        _cleanup(
            lambda: _poll_until(
                lambda: ec2.describe_volumes(VolumeIds=[volume_b])["Volumes"][0]["State"],
                lambda s: s == "available",
                timeout_s=60,
                interval_s=3,
            )
        )

    ctx.on_cleanup(cleanup_attach_b)

    # terminal independent read: the device now names volume_b as attached
    attachments = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_b])["Volumes"][0]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "attached",
        timeout_s=60,
        interval_s=3,
    )
    assert attachments[0]["Device"] == "/dev/sdf", f"expected volume_b attached at /dev/sdf, got {attachments!r}"


# ===== helpers =====
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
    "InvalidInstanceID.NotFound", "InvalidAttachmentID.NotFound", "InvalidVolume.NotFound",
})
_BUSY = frozenset({"DependencyViolation", "InvalidNetworkInterface.InUse", "VolumeInUse"})


def _cleanup(fn: Callable[[], Any], *done_codes: str) -> None:
    """Run one teardown call: a resource already gone (or a code in done_codes) returns; one AWS
    is still releasing is retried every 2 s for up to 30 s; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE or code in done_codes:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any]) -> tuple:
    """Call fn(); return (code, message) of its AWS error. A success raises."""
    try:
        result = fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
