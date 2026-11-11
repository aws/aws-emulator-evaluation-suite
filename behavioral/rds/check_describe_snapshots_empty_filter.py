"""describe-snapshots-empty-filter."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-snapshots-empty-filter"
GROUP = 'snapshots'
SERVICES = ['rds']


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _instance(rds, ident):
    try:
        insts = rds.describe_db_instances(DBInstanceIdentifier=ident).get("DBInstances", [])
        return insts[0] if insts else None
    except ClientError:
        return None


def _snapshot(rds, snap_id):
    try:
        snaps = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id).get("DBSnapshots", [])
        return snaps[0] if snaps else None
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=10.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBSnapshots with no filters returns every snapshot in the account, not an
    empty or scoped-down subset: a freshly created manual snapshot must show up in the
    unfiltered listing by its own identifier."""
    rds = ctx.client("rds")
    ident = ctx.unique_name("sim2real-behav-dbi-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=ident,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        # "admin" is a reserved admin-user-name word for the postgres engine on RDS.
        MasterUsername="sim2realadmin",
        MasterUserPassword=_make_password(),
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=ident, SkipFinalSnapshot=True)
    )
    _poll_until(
        lambda: _instance(rds, ident),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} available",
    )

    snap_id = ctx.unique_name("sim2real-behav-snap-")
    rds.create_db_snapshot(
        DBInstanceIdentifier=ident,
        DBSnapshotIdentifier=snap_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    # RDS refuses DeleteDBSnapshot while a manual snapshot is still "creating"; wait for it to
    # reach a deletable state so cleanup does not silently fail and leak it.
    _poll_until(
        lambda: _snapshot(rds, snap_id),
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"snapshot {snap_id} available",
    )

    resp = rds.describe_db_snapshots()
    assert "DBSnapshots" in resp
    ids = [s.get("DBSnapshotIdentifier") for s in resp["DBSnapshots"]]
    assert snap_id in ids, f"expected {snap_id} in unfiltered DescribeDBSnapshots, got {ids!r}"


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
