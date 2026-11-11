"""op-contract-disable-fast-launch."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-fast-launch"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableFastLaunch with DryRun answers DryRunOperation, a nonexistent AMI fails with
    InvalidAMIID.NotFound, and an owned Linux AMI fails with InvalidRequest (exact messages) and has
    no fast-launch record."""
    ec2 = ctx.client("ec2")
    bogus_image_id = "ami-00000000deadbeef0"

    err = _rejected(lambda: ec2.disable_fast_launch(ImageId=bogus_image_id, DryRun=True))
    assert err["Code"] == "DryRunOperation", f"expected DryRunOperation, got {err['Code']}"
    assert err["Message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {err['Message']!r}"
    )

    err = _rejected(lambda: ec2.disable_fast_launch(ImageId=bogus_image_id))
    assert err["Code"] == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {err['Code']}"
    assert err["Message"] == f"The image id '[{bogus_image_id}]' does not exist", (
        f"unexpected InvalidAMIID.NotFound message: {err['Message']!r}"
    )

    image_id = _create_minimal_ami(ctx)
    err = _rejected(lambda: ec2.disable_fast_launch(ImageId=image_id))
    assert err["Code"] == "InvalidRequest", f"expected InvalidRequest for a non-Windows AMI, got {err['Code']}"
    assert err["Message"] == (
        "Can't disable EC2 Fast Launch. EC2 Fast Launch is only available for the Windows "
        "operating system platform."
    ), (
        f"unexpected InvalidRequest message: {err['Message']!r}"
    )

    described = ec2.describe_fast_launch_images(ImageIds=[image_id])["FastLaunchImages"]
    assert described == [], f"expected no fast-launch record for a never-enabled AMI, got {described}"


def _rejected(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
    what: str = "condition",
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {what}, last value: {value}")


def _deregister_image_ignore(ctx, image_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        ):
            raise


def _create_minimal_ami(ctx) -> str:
    """Register a minimal, owned EBS-backed AMI without launching an instance."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}]}
        ],
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
        what=f"volume {volume_id} available",
    )

    snap = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}]}
        ],
    )
    snapshot_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=120,
        interval_s=4,
        what=f"snapshot {snapshot_id} completed",
    )

    image = ec2.register_image(
        Name=ctx.unique_name("sim2real-behav-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id, "VolumeType": "gp3"}}],
    )
    image_id = image["ImageId"]
    ctx.on_cleanup(lambda: _deregister_image_ignore(ctx, image_id))

    def _image_state():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        return images[0]["State"] if images else "pending"

    state = _poll_until(
        _image_state,
        lambda s: s in ("available", "invalid", "failed"),
        timeout_s=60,
        interval_s=3,
        what=f"image {image_id} available",
    )
    assert state == "available", f"image never became available: {state}"
    return image_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
