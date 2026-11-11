"""op-contract-detach-image-watermark."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detach-image-watermark"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachImageWatermark on an owned AMI with no watermark succeeds with Return false and lists no
    watermarks; after the AMI is deregistered the same call fails with InvalidAMIID.NotFound and its
    exact message."""

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "detach_image_watermark"):
        raise AssertionError("detach_image_watermark not supported by installed botocore")

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, "volume", ctx.unique_name("sim2real-wmvol-")),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )

    snap_id = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=_tag_spec(ctx, "snapshot", ctx.unique_name("sim2real-wmsnap-")),
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))

    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180.0,
        interval_s=5.0,
    )

    image_id = ec2.register_image(
        Name=ctx.unique_name("sim2real-wm-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
    )["ImageId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.deregister_image(ImageId=image_id)))

    _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )

    resp = ec2.detach_image_watermark(
        ImageId=image_id, WatermarkKey=f"{account_id}:sim2real-never-attached"
    )
    assert resp["Return"] is False, resp

    # Independent read at the destination: the mutating call's own Return=False is not
    # evidence on its own — confirm via a different operation that the image genuinely
    # carries no watermark (neither before this call's target nor as a result of it).
    watermarks = ec2.describe_images(ImageIds=[image_id])["Images"][0].get("ImageWatermarks", [])
    assert watermarks == [], watermarks

    # Deregister the AMI, then call the operation with its now-dead ID: an AWS-issued ID passes the
    # format check, so this reaches the not-found boundary rather than the format one.
    ec2.deregister_image(ImageId=image_id)

    code, message = _client_error(
        lambda: ec2.detach_image_watermark(
            ImageId=image_id, WatermarkKey=f"{account_id}:sim2real-x"
        )
    )
    assert code == "InvalidAMIID.NotFound", code
    expected_message = f"The image id '[{image_id}]' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        ):
            raise


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
