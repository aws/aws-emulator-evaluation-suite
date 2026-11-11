"""delete-nonexistent-snapshot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-snapshot"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_SNAPSHOT_NOT_FOUND = "DBSnapshotNotFound"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": "delete-nonexistent-snapshot"},
]


def _poll(fn, pred, *, timeout_s, interval_s=15):
    """Poll fn() until pred(value) or the deadline; returns the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _instance(rds, inst_id):
    """DescribeDBInstances for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _wait_instance_available(rds, inst_id, *, timeout_s=2100):
    inst = _poll(
        lambda: _instance(rds, inst_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=timeout_s,
    )
    assert inst is not None and inst.get("DBInstanceStatus") == "available", (
        f"DB instance {inst_id} did not reach 'available' within {timeout_s}s; "
        f"last status {(inst or {}).get('DBInstanceStatus')!r}"
    )
    return inst


def _delete_instance(rds, inst_id, *, wait_s=0):
    """Best-effort teardown: delete an instance with no final snapshot, optionally
    waiting until it is gone."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
    if wait_s:
        _poll(lambda: _instance(rds, inst_id), lambda i: i is None, timeout_s=wait_s, interval_s=20)


def _snapshot(rds, snap_id):
    """DescribeDBSnapshots for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_DB_SNAPSHOT_NOT_FOUND:
            return None
        raise


def _drop_snapshot(rds, snap_id):
    """Best-effort snapshot teardown."""
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _error_code(fn):
    """Call fn(); return the botocore Error.Code and Error.Message. Raises if fn() unexpectedly
    succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBSnapshot succeeds on a real manual snapshot, an independent read confirms it is gone, and a
    second delete of that id is rejected with DBSnapshotNotFound."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-behav-snapdel-")
    snapshot_id = ctx.unique_name("sim2real-behav-snapdel-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        StorageType="gp2",
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real123!",
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id, wait_s=1200))
    _wait_instance_available(rds, instance_id)

    rds.create_db_snapshot(
        DBSnapshotIdentifier=snapshot_id, DBInstanceIdentifier=instance_id, Tags=_MANAGED_TAGS
    )
    ctx.on_cleanup(lambda: _drop_snapshot(rds, snapshot_id))
    snap = _poll(
        lambda: _snapshot(rds, snapshot_id),
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=1800,
    )
    assert snap is not None and snap.get("Status") == "available", (
        f"snapshot {snapshot_id} did not reach 'available'; last {snap!r}"
    )

    # --- Positive control: DeleteDBSnapshot on a REAL, available snapshot succeeds.
    rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)

    # --- Independent read: the deleted snapshot is genuinely gone.
    gone_code, gone_message = _error_code(lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id))
    assert gone_code == ERR_DB_SNAPSHOT_NOT_FOUND, (
        f"expected {ERR_DB_SNAPSHOT_NOT_FOUND} reading a deleted snapshot, got {gone_code!r}"
    )
    assert gone_message == f"DBSnapshot not found: {snapshot_id}", gone_message

    # --- The actual contract under test: deleting that now-nonexistent id AGAIN raises
    # the same specific not-found code -- not a generic 400, not a silent no-op success.
    code, message = _error_code(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    assert code == ERR_DB_SNAPSHOT_NOT_FOUND, f"expected {ERR_DB_SNAPSHOT_NOT_FOUND}, got {code!r}"
    assert message == f"DBSnapshot not found: {snapshot_id}", message


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
