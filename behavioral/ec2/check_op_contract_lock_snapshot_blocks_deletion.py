"""op-contract-lock-snapshot-blocks-deletion."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

CHECK = "op-contract-lock-snapshot-blocks-deletion"
GROUP = "error-semantics"
SERVICES = ["ec2"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LockSnapshot in governance mode blocks deletion until unlocked; malformed lock params reject."""
    ec2 = ctx.client("ec2")
    az = _first_available_az(ctx)
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
            }
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
        Description="sim2real-lock-snapshot-contract",
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}],
            }
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snapshot_id))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180.0,
        interval_s=5.0,
    )

    # --- error boundary: mutually exclusive LockDuration/ExpirationDate must be rejected ---
    from datetime import datetime, timedelta, timezone

    expiration = (datetime.now(timezone.utc) + timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    code, message = _error(
        lambda: ec2.lock_snapshot(
            SnapshotId=snapshot_id,
            LockMode="governance",
            LockDuration=1,
            ExpirationDate=expiration,
        )
    )
    assert code == "InvalidRequest", f"unexpected error code: {code!r}"
    assert message == (
        "You must specify either ExpirationDate or LockDuration in the request, but not both."
    ), f"unexpected error message: {message!r}"

    # --- success path: lock in governance mode, verify the state, then unlock ---
    # (GetSnapshotLockStatus is not available on this EC2 client/API version, so the lock
    # state is verified from the LockSnapshot response itself, and the unlock is verified
    # via its actual effect: deletion becoming possible again.)
    lock_resp = ec2.lock_snapshot(
        SnapshotId=snapshot_id, LockMode="governance", LockDuration=1
    )
    assert lock_resp["LockState"] == "governance"
    assert lock_resp["LockDuration"] == 1

    # a locked snapshot cannot be deleted
    delete_code, delete_message = _error(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    assert delete_code == "SnapshotLocked", (
        f"expected deletion of a locked snapshot to be rejected with "
        f"SnapshotLocked, got {delete_code!r}"
    )
    assert delete_message == f"The snapshot '{snapshot_id}' is locked.", f"unexpected SnapshotLocked message {delete_message!r}"
    # independent read: the blocked delete must not have taken effect
    still_there = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"]
    assert still_there and still_there[0]["SnapshotId"] == snapshot_id, (
        f"snapshot {snapshot_id} should still exist after a rejected delete, got {still_there!r}"
    )

    # unlocking (allowed in governance mode) restores deletability; the unlock itself can take
    # a moment to fully take effect, so poll the actual deletion effect rather than a status field.
    ec2.unlock_snapshot(SnapshotId=snapshot_id)
    _poll_until(
        lambda: _try_delete_snapshot(ec2, snapshot_id),
        lambda deleted: deleted,
        timeout_s=30.0,
        interval_s=2.0,
    )

    # deletes prove gone and unusable: an independent read must now report not-found, and a
    # further mutation against the dead id must fail the same way
    gone_code, gone_message = _error(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])
    )
    assert gone_code == "InvalidSnapshot.NotFound", (
        f"expected the deleted snapshot to read back as InvalidSnapshot.NotFound, got {gone_code!r}"
    )
    assert gone_message == f"The snapshot '{snapshot_id}' does not exist.", f"unexpected not-found message {gone_message!r}"
    reuse_code, reuse_message = _error(lambda: ec2.unlock_snapshot(SnapshotId=snapshot_id))
    assert reuse_code == "InvalidSnapshot.NotFound", (
        f"expected a mutation on the deleted snapshot id to fail the same way, got {reuse_code!r}"
    )
    assert reuse_message == f"The snapshot '{snapshot_id}' does not exist.", f"unexpected not-found message {reuse_message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _try_delete_snapshot(ec2, snapshot_id: str) -> bool:
    """True once DeleteSnapshot succeeds; False while the snapshot is still locked."""
    from botocore.exceptions import ClientError

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
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not azs:
        raise AssertionError("no available Availability Zones found")
    return azs[0]["ZoneName"]


def _delete_snapshot(ec2, snapshot_id: str) -> None:
    try:
        ec2.unlock_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
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
