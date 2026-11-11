"""op-contract-cancel-image-launch-permission."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-cancel-image-launch-permission"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelImageLaunchPermission removes the explicit launch permission the caller granted itself on
    an AMI it owns, and fails with InvalidAMIID.NotFound and its exact message on a public AMI where
    the caller holds no per-account permission."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # ---- Positive control: the operation succeeds on an AMI the caller owns ----
    image_id = _register_owned_image(ctx, ec2)

    ec2.modify_image_attribute(ImageId=image_id, LaunchPermission={"Add": [{"UserId": account_id}]})
    granted = ec2.describe_image_attribute(ImageId=image_id, Attribute="launchPermission")
    assert any(p.get("UserId") == account_id for p in granted["LaunchPermissions"]), (
        f"expected {account_id} in LaunchPermissions after grant, got {granted['LaunchPermissions']}"
    )

    ec2.cancel_image_launch_permission(ImageId=image_id)

    after = ec2.describe_image_attribute(ImageId=image_id, Attribute="launchPermission")
    assert not any(p.get("UserId") == account_id for p in after["LaunchPermissions"]), (
        f"expected {account_id} removed from LaunchPermissions after cancel, got {after['LaunchPermissions']}"
    )

    # ---- Negative: a public AMI never shared with the caller's account directly ----
    real_ami_id = _latest_al2023_ami(ctx)

    try:
        resp = ec2.cancel_image_launch_permission(ImageId=real_ami_id)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidAMIID.NotFound", (
            f"expected InvalidAMIID.NotFound, got {e.response['Error']}"
        )
        assert e.response["Error"]["Message"] == (
            f'The image id "{real_ami_id}" belongs to an AMI which does not exist or is not '
            "shared directly with your account."
        ), e.response["Error"]["Message"]
    else:
        raise AssertionError(
            f"expected CancelImageLaunchPermission on a public AMI never shared with the "
            f"caller to be rejected as InvalidAMIID.NotFound, but it succeeded: {resp}"
        )


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _register_owned_image(ctx, ec2) -> str:
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{
            "ResourceType": "volume",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cilp-")}],
        }],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_volume(VolumeId=vol_id)))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=90,
        interval_s=3,
    )

    snap_id = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cilp-")}],
        }],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_snapshot(SnapshotId=snap_id)))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=300,
        interval_s=5,
    )

    image_id = ec2.register_image(
        Name=ctx.unique_name("sim2real-cilp-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
        EnaSupport=True,
    )["ImageId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.deregister_image(ImageId=image_id)))
    _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=3,
    )
    return image_id


def _ignore_error(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
            "InvalidSnapshot.NotFound",
            "InvalidVolume.NotFound",
        ):
            raise


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
