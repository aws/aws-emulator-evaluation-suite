"""lock-snapshot-lock-duration-past-the-maximum-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lock-snapshot-lock-duration-past-the-maximum-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LockSnapshot rejects a LockDuration one day past its 36500-day maximum, and the
    maximum value itself is accepted and reported back unchanged.
    """
    ec2 = ctx.client("ec2")
    az = _first_available_az(ctx)
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        Description="sim2real-lock-duration-range",
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}]}
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda sid=snapshot_id: _delete_snapshot(ec2, sid))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180.0,
        interval_s=5.0,
    )

    # error boundary: one day past the documented 36500-day maximum
    code, message = _error(
        lambda: ec2.lock_snapshot(SnapshotId=snapshot_id, LockMode="governance", LockDuration=36501)
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '36501' at 'lockDuration' failed to satisfy "
        "constraint: Member must have value less than or equal to 36500"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the rejected request must not have locked the snapshot: an unlocked snapshot deletes cleanly
    assert _can_delete_snapshot(ec2, snapshot_id), (
        "a rejected LockDuration must leave the snapshot unlocked and deletable"
    )

    # a fresh snapshot carries the positive control: the maximum value itself is accepted
    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        Description="sim2real-lock-duration-range-2",
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap2-")}]}
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda sid=snapshot_id: _delete_snapshot(ec2, sid))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180.0,
        interval_s=5.0,
    )

    # positive control: the legal neighbour -- the maximum value itself -- is accepted
    lock_resp = ec2.lock_snapshot(SnapshotId=snapshot_id, LockMode="governance", LockDuration=36500)
    assert lock_resp["LockDuration"] == 36500, f"expected LockDuration 36500 echoed back, got {lock_resp!r}"
    assert lock_resp["LockState"] == "governance", f"expected LockState governance, got {lock_resp!r}"

    ec2.unlock_snapshot(SnapshotId=snapshot_id)
    _poll_until(
        lambda: _can_delete_snapshot(ec2, snapshot_id),
        lambda done: done,
        timeout_s=30.0,
        interval_s=2.0,
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _can_delete_snapshot(ec2, snapshot_id: str) -> bool:
    """True once DeleteSnapshot succeeds; False while SnapshotLocked blocks it."""
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "SnapshotLocked":
            raise
        return False
    return True


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _first_available_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    if not azs:
        raise AssertionError("no available Availability Zones found")
    return azs[0]["ZoneName"]


def _delete_snapshot(ec2, snapshot_id: str) -> None:
    try:
        ec2.unlock_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidSnapshot.NotFound", "SnapshotLockNotFound"):
            raise
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


def _delete_volume(ec2, volume_id: str, timeout_s: float = 60.0) -> None:
    """Teardown: delete the volume, retrying VolumeInUse/IncorrectState every 2 s up to timeout_s;
    not found is done, anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVolume.NotFound":
                return
            if code not in ("VolumeInUse", "IncorrectState") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
