"""snapshot-creation-timestamp-preserved-through-copy."""
from __future__ import annotations

import datetime
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-creation-timestamp-preserved-through-copy"
GROUP = "representation"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real", "Value": CHECK},
]
_POLL_INTERVAL_S = 2.0
# A whole-second timestamp tick, so the copy cannot be stamped in the original's second.
_TIMESTAMP_TICK_S = 1.1


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_past(moment: datetime.datetime) -> None:
    """Sleep until the wall clock is one timestamp tick past moment (at most one tick)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    remaining = (moment - now).total_seconds() + _TIMESTAMP_TICK_S
    if remaining > 0:
        time.sleep(min(remaining, _TIMESTAMP_TICK_S))


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """The original manual snapshot's SnapshotCreateTime is left unchanged by CopyDBSnapshot,
    and is distinct from the copy's own SnapshotCreateTime (the copy records when the copy
    itself was created, not when the source snapshot was taken)."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-snaptime-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    _wait_for_instance_status(rds, db_id, "available", timeout_s=_budget_s(ctx, 900), ctx=ctx)

    snap_id = ctx.unique_name("sim2real-snap-orig-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snap_id))
    original = _wait_for_snapshot_status(rds, snap_id, "available", timeout_s=_budget_s(ctx, 900), ctx=ctx)
    original_create_time = original["SnapshotCreateTime"]
    _wait_past(original_create_time)

    copy_id = ctx.unique_name("sim2real-snap-copy-")
    rds.copy_db_snapshot(
        SourceDBSnapshotIdentifier=snap_id, TargetDBSnapshotIdentifier=copy_id, Tags=_TAGS
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, copy_id))
    copy = _wait_for_snapshot_status(rds, copy_id, "available", timeout_s=_budget_s(ctx, 900), ctx=ctx)
    copy_create_time = copy["SnapshotCreateTime"]

    # Re-describe the ORIGINAL after the copy completed: its own creation timestamp must be
    # byte-for-byte unchanged by the copy operation.
    original_after_copy = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
    assert original_after_copy["SnapshotCreateTime"] == original_create_time, (
        f"original snapshot's SnapshotCreateTime changed after copy: "
        f"{original_create_time!r} -> {original_after_copy['SnapshotCreateTime']!r}"
    )

    # The copy has its OWN creation time, distinct from the original's.
    assert copy_create_time != original_create_time, (
        f"copy's SnapshotCreateTime ({copy_create_time!r}) is identical to the original's "
        f"({original_create_time!r}); expected the copy to record its own creation moment"
    )


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float, ctx=None) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return inst
        if inst["DBInstanceStatus"] == "failed":
            raise AssertionError(f"instance {db_id} entered terminal bad status 'failed'")
        time.sleep(_POLL_INTERVAL_S)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"DB instance {db_id} {status!r}: the run budget ended first; not graded")
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _wait_for_snapshot_status(rds: Any, snap_id: str, status: str, *, timeout_s: float, ctx=None) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        snap = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
        last = snap["Status"]
        if last == status:
            return snap
        if last == "failed":
            raise AssertionError(f"snapshot {snap_id} entered terminal status 'failed'")
        time.sleep(_POLL_INTERVAL_S)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"snapshot {snap_id} {status!r}: the run budget ended first; not graded")
    raise AssertionError(f"snapshot {snap_id} never reached status={status!r} in {timeout_s}s, last={last!r}")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFoundFault":
            raise


def _delete_snapshot(rds: Any, snap_id: str) -> None:
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFoundFault":
            raise


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
