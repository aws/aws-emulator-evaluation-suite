"""op-contract-unlock-snapshot."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-unlock-snapshot"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlockSnapshot transitions a governance-locked snapshot back to unlocked; a bogus
    snapshot id is rejected as InvalidSnapshot.NotFound."""
    ec2 = ctx.client("ec2")

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az = azs[0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
            }
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _wait_volume_state(ctx, volume_id, {"available"})

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}],
            }
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_snapshot_state(ctx, snapshot_id, {"completed"})

    ec2.lock_snapshot(SnapshotId=snapshot_id, LockMode="governance", LockDuration=1)

    def lock_state():
        from botocore.exceptions import ClientError

        try:
            resp = ec2.describe_locked_snapshots(SnapshotIds=[snapshot_id])
        except ClientError as e:
            if e.response["Error"]["Code"] == "SnapshotLockNotFound":
                # real EC2 raises this instead of returning an empty list when the
                # snapshot has no lock (or once a lock has just been removed)
                return None
            raise
        snaps = resp.get("Snapshots", [])
        return snaps[0].get("LockState") if snaps else None

    locked_state = _poll_until(lock_state, lambda s: s == "governance", timeout_s=30.0)
    assert locked_state == "governance", f"expected LockState 'governance', got {locked_state!r}"

    # success path: unlock it
    resp = ec2.unlock_snapshot(SnapshotId=snapshot_id)
    assert resp["SnapshotId"] == snapshot_id, (
        f"expected UnlockSnapshot response SnapshotId {snapshot_id!r}, got {resp.get('SnapshotId')!r}"
    )

    unlocked_state = _poll_until(lock_state, lambda s: s in (None, "unlocked"), timeout_s=30.0)
    assert unlocked_state in (None, "unlocked"), unlocked_state

    # error boundary: a well-formed snapshot id that was never issued.
    bogus_id = "snap-0000000000000dead"
    code, message = _error_code(lambda: ec2.unlock_snapshot(SnapshotId=bogus_id))
    assert code == "InvalidSnapshot.NotFound", f"code={code} message={message!r}"
    assert message == f"The snapshot '{bogus_id}' does not exist.", message


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_volume_state(ctx, volume_id, states, timeout_s=60.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_volumes(VolumeIds=[volume_id])
        return resp["Volumes"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s, interval_s=2.0)


def _wait_snapshot_state(ctx, snapshot_id, states, timeout_s=300.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
        return resp["Snapshots"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s, interval_s=5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
