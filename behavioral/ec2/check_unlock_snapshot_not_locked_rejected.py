"""unlock-snapshot-not-locked-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "unlock-snapshot-not-locked-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlockSnapshot rejects a snapshot that carries no lock, while the identical call on the
    same snapshot succeeds once it has been locked.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_UnlockSnapshot.html
    """
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        TagSpecifications=[_tag_spec("volume", ctx.unique_name("sim2real-behav-us-vol-"))],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _wait_volume_state(ec2, volume_id, {"available"})

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[_tag_spec("snapshot", ctx.unique_name("sim2real-behav-us-snap-"))],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_snapshot_state(ec2, snapshot_id, {"completed"})

    # error boundary: the snapshot has never been locked.
    code, message = _error_code(lambda: ec2.unlock_snapshot(SnapshotId=snapshot_id))
    assert code == "SnapshotLockNotFound", f"expected SnapshotLockNotFound, got {code!r}"
    assert message == f"The specified snapshot '{snapshot_id}' is not locked.", message

    # positive control: the identical call succeeds once the snapshot is actually locked.
    ec2.lock_snapshot(SnapshotId=snapshot_id, LockMode="governance", LockDuration=1)

    def lock_state():
        try:
            resp = ec2.describe_locked_snapshots(SnapshotIds=[snapshot_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "SnapshotLockNotFound":
                return None
            raise
        snaps = resp.get("Snapshots", [])
        return snaps[0].get("LockState") if snaps else None

    locked_state = _poll_until(lock_state, lambda s: s == "governance", timeout_s=30.0)
    assert locked_state == "governance", f"expected LockState 'governance', got {locked_state!r}"

    resp = ec2.unlock_snapshot(SnapshotId=snapshot_id)
    assert resp["SnapshotId"] == snapshot_id, (
        f"expected UnlockSnapshot response SnapshotId {snapshot_id!r}, got {resp.get('SnapshotId')!r}"
    )

    unlocked_state = _poll_until(lock_state, lambda s: s in (None, "unlocked"), timeout_s=30.0)
    assert unlocked_state in (None, "unlocked"), (
        f"expected the lock state to clear after UnlockSnapshot, got {unlocked_state!r}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_volume_state(ec2, volume_id, states, timeout_s=60.0):
    def probe():
        return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s, interval_s=2.0)


def _wait_snapshot_state(ec2, snapshot_id, states, timeout_s=300.0):
    def probe():
        return ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s, interval_s=5.0)


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
