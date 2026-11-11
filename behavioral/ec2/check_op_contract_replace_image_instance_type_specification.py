"""op-contract-replace-image-instance-type-specification."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-image-instance-type-specification"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceImageInstanceTypeSpecification sets/clears an AMI's instance-type
    compatibility spec (success contract), and rejects an unknown AMI with
    InvalidAMIID.NotFound."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    vol = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3",
                             TagSpecifications=_tags("volume", ctx.unique_name("sim2real-riits-")))
    vol_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    _poll_until(lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
                lambda s: s == "available", timeout_s=90, interval_s=3)

    snap = ec2.create_snapshot(VolumeId=vol_id,
                                TagSpecifications=_tags("snapshot", ctx.unique_name("sim2real-riits-")))
    snap_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    _poll_until(lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
                lambda s: s == "completed", timeout_s=300, interval_s=5)

    image_name = ctx.unique_name("sim2real-riits-")
    image = ec2.register_image(
        Name=image_name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
        EnaSupport=True,
    )
    image_id = image["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image_id))
    _poll_until(lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
                lambda s: s == "available", timeout_s=120, interval_s=3)

    resp = ec2.replace_image_instance_type_specification(
        ImageId=image_id,
        InstanceTypeSpecification={
            "SupportedInstanceTypes": ["t3.*"],
            "UnsupportedInstanceTypes": ["t3.nano"],
        },
    )
    assert resp["ReturnValue"] is True

    # Independent read at the destination: DescribeImages (a different operation than
    # the one that mutated) surfaces the spec it just set. Poll for propagation rather
    # than trusting the mutating call's own ReturnValue as the terminal assertion.
    spec = _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0].get("InstanceTypeSpecification"),
        lambda s: s is not None,
        timeout_s=60, interval_s=3,
    )
    # DescribeImages echoes each entry as {"InstanceType": <str>} even though the
    # request took plain strings (confirmed against real AWS -- the request shape and
    # the response shape differ for this field).
    supported = [e["InstanceType"] for e in spec.get("SupportedInstanceTypes", [])]
    unsupported = [e["InstanceType"] for e in spec.get("UnsupportedInstanceTypes", [])]
    assert supported == ["t3.*"], f"expected SupportedInstanceTypes=['t3.*'], got {supported!r}"
    assert unsupported == ["t3.nano"], f"expected UnsupportedInstanceTypes=['t3.nano'], got {unsupported!r}"

    # Omitting the spec clears it (idempotent removal contract). Confirm the clear via
    # the same independent read, not the mutating call's own response.
    resp2 = ec2.replace_image_instance_type_specification(ImageId=image_id)
    assert resp2["ReturnValue"] is True

    cleared = _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0].get("InstanceTypeSpecification"),
        lambda s: not s or (not s.get("SupportedInstanceTypes") and not s.get("UnsupportedInstanceTypes")),
        timeout_s=60, interval_s=3,
    )
    assert not cleared or (not cleared.get("SupportedInstanceTypes") and not cleared.get("UnsupportedInstanceTypes")), (
        f"expected InstanceTypeSpecification to be cleared, got {cleared!r}"
    )

    # AMI IDs are not eligible for the 17-hex-char "long ID" format that
    # newer resource types (subnets, route tables, ...) use -- they stay at
    # the original 8-hex-char length, so a 17-char id like
    # "ami-1234567890abcdef0" is rejected up front as Malformed rather than
    # reaching the existence check. Use a well-formed (8-hex-char) but
    # unassigned id instead.
    #
    # Unlike some other AMI-attribute mutation calls, real AWS does *not*
    # hide the fact that ReplaceImageInstanceTypeSpecification's ImageId
    # doesn't exist behind a generic permission error -- it reports
    # InvalidAMIID.NotFound directly.
    code, message = _error(lambda: ec2.replace_image_instance_type_specification(
        ImageId="ami-12345678",
        InstanceTypeSpecification={"SupportedInstanceTypes": ["t3.*"]},
    ))
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    assert message == "The image id '[ami-12345678]' does not exist", (
        f"unexpected InvalidAMIID.NotFound message {message!r}")


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
