"""op-contract-reset-image-attribute."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-reset-image-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetImageAttribute clears a launch permission granted on an owned AMI; an unknown AMI id
    is rejected with InvalidAMIID.NotFound and its message."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    vol_id = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3",
        TagSpecifications=_tags("volume", ctx.unique_name("sim2real-ria-")),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    _poll_until(lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
                lambda s: s == "available", timeout_s=90, interval_s=3)

    snap_id = ec2.create_snapshot(
        VolumeId=vol_id, TagSpecifications=_tags("snapshot", ctx.unique_name("sim2real-ria-")),
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    _poll_until(lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
                lambda s: s == "completed", timeout_s=300, interval_s=5)

    image_id = ec2.register_image(
        Name=ctx.unique_name("sim2real-ria-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
        EnaSupport=True,
    )["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image_id))
    _poll_until(lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
                lambda s: s == "available", timeout_s=120, interval_s=3)

    ec2.modify_image_attribute(ImageId=image_id, LaunchPermission={"Add": [{"UserId": "111122223333"}]})
    before = ec2.describe_image_attribute(ImageId=image_id, Attribute="launchPermission")
    assert any(p.get("UserId") == "111122223333" for p in before["LaunchPermissions"]), (
        "launch permission was not granted before reset")

    ec2.reset_image_attribute(ImageId=image_id, Attribute="launchPermission")

    after = ec2.describe_image_attribute(ImageId=image_id, Attribute="launchPermission")
    assert after["LaunchPermissions"] == [], f"launch permissions were not cleared: {after['LaunchPermissions']}"

    # Here a 17-char "ami-1234567890abcdef0" is rejected as Malformed, so use an unassigned
    # 8-hex-char id. EC2 masks existence only for AMIs owned by others, not never-registered ids.
    code, message = _error(lambda: ec2.reset_image_attribute(
        ImageId="ami-12345678", Attribute="launchPermission"))
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    assert message == "The image id '[ami-12345678]' does not exist", (
        f"unexpected InvalidAMIID.NotFound message {message!r}")


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises."""
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
