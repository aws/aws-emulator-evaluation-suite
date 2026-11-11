"""op-contract-disable-image."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-image"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableImage: disabling a real, owned AMI flips its state to `disabled` (visible in
    both the default and IncludeDisabled listings for the owner) and blocks new launches;
    a nonexistent AMI is rejected with the specific NotFound code."""
    ec2 = ctx.client("ec2")
    image_id = _create_test_ami(ctx)

    resp = ec2.disable_image(ImageId=image_id)
    assert resp["Return"] is True, f"expected DisableImage to return Return=True, got {resp!r}"

    described = ec2.describe_images(ImageIds=[image_id], IncludeDisabled=True)["Images"][0]
    assert described["State"] == "disabled", f"unexpected state: {described['State']}"

    # A disabled AMI that you own remains visible to you in the default (non-disabled)
    # listing too -- `IncludeDisabled` only affects visibility for other accounts a
    # disabled AMI may have been shared with, not the owner's own view of it. Confirm
    # it's still there, still reporting the disabled state.
    default_listing = ec2.describe_images(ImageIds=[image_id])["Images"]
    assert len(default_listing) == 1, (
        f"expected the owner to still see their own disabled AMI by default: {default_listing}"
    )
    assert default_listing[0]["State"] == "disabled", (
        f"unexpected state in default listing: {default_listing[0]['State']}"
    )

    # A disabled AMI can no longer be launched.
    code, message = _client_error(lambda: ec2.run_instances(ImageId=image_id, MinCount=1, MaxCount=1, SubnetId=ctx.network().subnet_ids[0]))
    assert code == "InvalidAMIID.Unavailable", f"expected the disabled AMI to be unusable for launch, got {code}"
    expected_message = f"AMI '{image_id}' is disabled, and cannot be run"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    code, message = _client_error(lambda: ec2.disable_image(ImageId="ami-00000000deadbeef0"))
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    expected_message = "Invalid ImageId: ami-00000000deadbeef0"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_test_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]

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
