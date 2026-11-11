"""snapshot-create-from-volume-and-describe."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _get_az(ec2, instance_type="t3.micro"):
    """An available AZ that actually offers *instance_type* (falls back to any)."""
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        ).get("InstanceTypeOfferings", [])
        offered = {o["Location"] for o in offerings}
        for z in zones:
            if z in offered:
                return z
    except Exception:
        pass
    return zones[0]


def _wait_volume_state(ec2, volume_id, state, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return last
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} did not reach {state!r} within {timeout_s}s (last {last!r})")


def _wait_snapshot_completed(ec2, snapshot_id, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSnapshot.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        if last == "completed":
            return last
        time.sleep(3)
    raise AssertionError(f"snapshot {snapshot_id} did not complete within {timeout_s}s (last {last!r})")


def _wait_snapshot_gone(ec2, snapshot_id, timeout_s=60):
    """Poll DescribeSnapshots until it reports InvalidSnapshot.NotFound; return that error (code, message)."""
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        time.sleep(2)
    raise AssertionError(
        f"snapshot {snapshot_id} still visible via DescribeSnapshots {timeout_s}s after delete "
        f"(last State {last_state!r})"
    )


def _cleanup_snapshot(ec2, snapshot_id):
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidSnapshot.NotFound":
            raise


def _cleanup_volume(ec2, volume_id):
    """Best-effort teardown: force-detach, wait available, delete."""
    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "InvalidVolume.NotFound"
            and not (err["Code"] == "IncorrectState" and "is in the 'available' state" in err.get("Message", ""))
        ):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                raise
            return
        if state == "available":
            break
        time.sleep(2)
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise

CHECK = "snapshot-create-from-volume-and-describe"
GROUP = 'ebs-lifecycle'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSnapshot transitions pending -> completed, references the source volume and its
    declared size, and once deleted the snapshot is gone from an independent DescribeSnapshots
    read and its id cannot be reused to create a new volume."""
    ec2 = ctx.client("ec2")
    az = _get_az(ec2)
    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup_volume(ec2, volume_id))
    _wait_volume_state(ec2, volume_id, "available")

    snapshot_id = ec2.create_snapshot(VolumeId=volume_id, Description="behavioral check snapshot", TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["SnapshotId"]
    ctx.on_cleanup(lambda: _cleanup_snapshot(ec2, snapshot_id))
    snap = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    assert snap["VolumeId"] == volume_id, (
        f"snapshot {snapshot_id} names VolumeId {snap.get('VolumeId')!r}, expected {volume_id!r}"
    )
    assert snap["State"] in ("pending", "completed"), (
        f"snapshot {snapshot_id} in unexpected initial State {snap.get('State')!r}"
    )

    _wait_snapshot_completed(ec2, snapshot_id)
    snap = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    assert snap["State"] == "completed", (
        f"snapshot {snapshot_id} ended in State {snap.get('State')!r}, expected 'completed'"
    )
    assert snap["VolumeSize"] == 1, (
        f"snapshot {snapshot_id} declares VolumeSize {snap.get('VolumeSize')!r}, expected 1"
    )

    ec2.delete_snapshot(SnapshotId=snapshot_id)
    gone_code, gone_message = _wait_snapshot_gone(ec2, snapshot_id)
    assert gone_code == "InvalidSnapshot.NotFound", (
        f"expected InvalidSnapshot.NotFound reading deleted snapshot {snapshot_id}, got {gone_code!r}"
    )
    assert gone_message == f"The snapshot '{snapshot_id}' does not exist.", gone_message

    reused = None
    reuse_code = reuse_message = None
    try:
        reused = ec2.create_volume(AvailabilityZone=az, SnapshotId=snapshot_id)
    except ClientError as exc:
        reuse_code = exc.response.get("Error", {}).get("Code")
        reuse_message = exc.response.get("Error", {}).get("Message")
    if reused is not None:
        ctx.on_cleanup(lambda: _cleanup_volume(ec2, reused["VolumeId"]))
    assert reuse_code == "InvalidSnapshot.NotFound", (
        f"expected InvalidSnapshot.NotFound reusing deleted snapshot {snapshot_id}, got "
        f"{reuse_code!r} (CreateVolume returned {reused!r})"
    )
    assert reuse_message == "Snapshot does not exist", reuse_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
