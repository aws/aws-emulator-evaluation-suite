"""op-contract-delete-snapshot-in-use-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-snapshot-in-use-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSnapshot succeeds on a standalone snapshot; fails InvalidSnapshot.InUse while
    the snapshot backs a registered AMI."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    tag = [{"Key": "sim2real", "Value": "1"}]

    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
    )

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": tag}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _best_effort_delete_snapshot(ec2, snapshot_id))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda state: state == "completed",
        timeout_s=180,
        interval_s=5,
    )

    image_id = ec2.register_image(
        Name=ctx.unique_name("sim2real-behav-snap-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/sda1",
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": snapshot_id}}
        ],
        TagSpecifications=[{"ResourceType": "image", "Tags": tag}],
    )["ImageId"]

    def _cleanup_image() -> None:
        try:
            ec2.deregister_image(ImageId=image_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidAMIID.NotFound",
                "InvalidAMIID.Unavailable",
            ):
                raise

    ctx.on_cleanup(_cleanup_image)
    _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
    )

    code, message = _error_of(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    assert code == "InvalidSnapshot.InUse", f"expected InvalidSnapshot.InUse, got {code!r}"
    assert message == f"The snapshot {snapshot_id} is currently in use by {image_id}", message

    survivor_state = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
    assert survivor_state == "completed", (
        f"expected the rejected delete to leave the snapshot 'completed', got {survivor_state!r}"
    )

    # Deregistration releases the snapshot asynchronously, so the delete is retried briefly.
    ec2.deregister_image(ImageId=image_id)
    resp = _poll_until(
        lambda: _try_delete_snapshot(ec2, snapshot_id),
        lambda ok: ok is True,
        timeout_s=60,
    )
    assert resp is True, f"expected the delete to succeed once the AMI was deregistered, got {resp!r}"

    code, message = _error_of(lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id]))
    assert code == "InvalidSnapshot.NotFound", f"expected NotFound, got {code!r}"
    assert message == f"The snapshot '{snapshot_id}' does not exist.", message


def _best_effort_delete_snapshot(ec2: Any, snapshot_id: str) -> None:
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


def _try_delete_snapshot(ec2: Any, snapshot_id: str) -> bool:
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
        return True
    except Exception:
        return False


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return the ClientError (code, message) fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
