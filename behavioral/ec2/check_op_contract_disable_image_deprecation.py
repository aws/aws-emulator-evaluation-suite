"""op-contract-disable-image-deprecation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-image-deprecation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableImageDeprecation: cancels a real deprecation schedule on an owned AMI and
    asserts DeprecationTime is cleared; a nonexistent AMI is rejected with the specific
    NotFound code."""
    ec2 = ctx.client("ec2")
    image_id = _create_test_ami(ctx)

    deprecate_at = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ec2.enable_image_deprecation(ImageId=image_id, DeprecateAt=deprecate_at)
    described = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    assert "DeprecationTime" in described, "deprecation schedule did not take effect"

    resp = ec2.disable_image_deprecation(ImageId=image_id)
    assert resp["Return"] is True

    described = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    assert "DeprecationTime" not in described, (
        f"DeprecationTime still present after disable: {described.get('DeprecationTime')}"
    )

    code, message = _client_error(lambda: ec2.disable_image_deprecation(ImageId="ami-00000000deadbeef0"))
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    expected_message = "Invalid ImageId: ami-00000000deadbeef0"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_test_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]

    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{
            "ResourceType": "volume",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
        }],
    )
    vol_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[vol_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snap = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}],
        }],
    )
    snap_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    image = ec2.register_image(
        Name=ctx.unique_name("sim2real-behav-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
        EnaSupport=True,
    )
    image_id = image["ImageId"]

    def _deregister():
        try:
            ec2.deregister_image(ImageId=image_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidAMIID.NotFound",
                "InvalidAMIID.Unavailable",
            ):
                raise

    ctx.on_cleanup(_deregister)
    ec2.get_waiter("image_available").wait(ImageIds=[image_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return image_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
