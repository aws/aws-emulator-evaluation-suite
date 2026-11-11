"""op-contract-deregister-image."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deregister-image"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterImage removes a self-owned AMI so it's no longer resolvable;
    deregistering it a second time 404s."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    volume_id = ec2.create_volume(
        Size=1,
        AvailabilityZone=az,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
            }
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_volume(VolumeId=volume_id)))

    def _vol_state():
        return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]

    vol_state = _poll_until(_vol_state, lambda s: s == "available", timeout_s=60, interval_s=2)
    assert vol_state == "available", f"expected volume state available, last={vol_state}"

    snapshot_id = ec2.create_snapshot(VolumeId=volume_id)["SnapshotId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id)))

    def _snap_state():
        return ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]

    snap_state = _poll_until(_snap_state, lambda s: s == "completed", timeout_s=120, interval_s=3)
    assert snap_state == "completed", f"expected snapshot state completed, last={snap_state}"

    image_name = ctx.unique_name("sim2real-behav-ami-")
    image_id = ec2.register_image(
        Name=image_name,
        Architecture="x86_64",
        VirtualizationType="hvm",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id}}],
        EnaSupport=True,
    )["ImageId"]

    def _cleanup_image():
        from botocore.exceptions import ClientError

        try:
            ec2.deregister_image(ImageId=image_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                raise

    ctx.on_cleanup(_cleanup_image)

    def _image_state():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        return images[0]["State"] if images else "gone"

    state = _poll_until(_image_state, lambda s: s in ("available", "failed"), timeout_s=120, interval_s=3)
    assert state == "available", f"registered image never became available, last={state}"

    # success path: deregister and confirm the image stops resolving
    ec2.deregister_image(ImageId=image_id)

    def _image_gone():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        if not images:
            return True
        return images[0]["State"] == "deregistered"

    assert _poll_until(_image_gone, lambda ok: ok, timeout_s=60, interval_s=2), (
        "image was neither removed nor marked deregistered after DeregisterImage"
    )

    # error boundary: deregistering the same (now-gone) image id again fails.
    # Immediately after deregistration AWS may still report the id as
    # transiently unavailable (InvalidAMIID.Unavailable) before it settles
    # into a full not-found state; both are legitimate rejections here.
    error = _error(lambda: ec2.deregister_image(ImageId=image_id))
    assert error["Code"] in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"), error

    # error boundary #2: a syntactically valid but never-issued image id also
    # gets rejected. Real AWS treats an all-zero id specially: rather than
    # reporting a clean not-found, it can flag the id itself as malformed
    # (the all-zero hex pattern fails its internal id validation), so both
    # outcomes are legitimate rejections here.
    error2 = _error(lambda: ec2.deregister_image(ImageId="ami-00000000000000000"))
    assert error2["Code"] in ("InvalidAMIID.NotFound", "InvalidAMIID.Malformed"), error2
    if error2["Code"] == "InvalidAMIID.Malformed":
        assert error2["Message"] == 'Invalid id: "ami-00000000000000000"', error2


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidSnapshot.NotFound",
            "InvalidVolume.NotFound",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
