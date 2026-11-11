"""describe-snapshot-attributes."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-snapshot-attributes"
GROUP = 'snapshots'
SERVICES = ['rds']


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _client_error(fn) -> dict:
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _instance(rds, ident):
    try:
        insts = rds.describe_db_instances(DBInstanceIdentifier=ident).get("DBInstances", [])
        return insts[0] if insts else None
    except ClientError:
        return None


def _snapshot(rds, snap_id):
    resp = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)
    snaps = resp.get("DBSnapshots", [])
    return snaps[0] if snaps else None


def _postgres_instance_kwargs(ident):
    return dict(
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBSnapshotAttributes on a manual snapshot echoes its id with an empty "restore"
    attribute; an unknown DBSnapshotIdentifier fails DBSnapshotNotFound.
    """
    rds = ctx.client("rds")
    ident = ctx.unique_name("sim2real-behav-dbi-")
    rds.create_db_instance(**_postgres_instance_kwargs(ident), DBSubnetGroupName=_network_db_subnet_group(ctx, rds))
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    _poll_until(
        lambda: _snapshot(rds, snap_id),
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"snapshot {snap_id} available",
    )

    resp = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap_id)
    result = resp["DBSnapshotAttributesResult"]
    assert result["DBSnapshotIdentifier"] == snap_id, (
        f"expected DescribeDBSnapshotAttributes to echo {snap_id!r}, "
        f"got {result['DBSnapshotIdentifier']!r}"
    )
    attrs = result.get("DBSnapshotAttributes")
    assert isinstance(attrs, list), f"expected a list of attributes, got {attrs!r}"
    restore_attr = next((a for a in attrs if a.get("AttributeName") == "restore"), None)
    assert restore_attr is not None, (
        f"expected a 'restore' attribute on an unshared manual snapshot, got {attrs!r}"
    )
    assert restore_attr.get("AttributeValues") == [], (
        f"a freshly created manual snapshot with no explicit shares must report an empty "
        f"restore AttributeValues, got {restore_attr.get('AttributeValues')!r}"
    )

    bogus_snap = ctx.unique_name("sim2real-behav-snap-missing-")
    err = _client_error(
        lambda: rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=bogus_snap)
    )
    assert err.get("Code") == "DBSnapshotNotFound", f"unexpected error code: {err.get('Code')}"
    expected = f"DBSnapshot not found: {bogus_snap}"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
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
