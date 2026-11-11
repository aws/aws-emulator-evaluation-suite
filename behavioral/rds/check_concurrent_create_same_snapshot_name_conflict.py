"""concurrent-create-same-snapshot-name-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "concurrent-create-same-snapshot-name-conflict"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateDBSnapshot calls with the same identifier: exactly one succeeds, the other
    is rejected with DBSnapshotAlreadyExistsFault, and exactly one snapshot with that identifier exists."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-snap-")
    snapshot_id = ctx.unique_name("sim2real-rds-snapshot-")

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        AllocatedStorage=20,
        StorageType="gp2",
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))
    _wait_for_instance_status(rds, instance_id, {"available"}, timeout_s=1800, interval_s=20)

    def _snap():
        return rds.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceIdentifier=instance_id,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(lambda: _capture(_snap))
        fut2 = pool.submit(lambda: _capture(_snap))
        outcome1 = fut1.result()
        outcome2 = fut2.result()

    outcomes = [outcome1, outcome2]
    successes = [o for o in outcomes if o["ok"]]
    failures = [o for o in outcomes if not o["ok"]]
    assert len(successes) == 1, f"expected exactly one CreateDBSnapshot to succeed: {outcomes}"
    assert len(failures) == 1, f"expected exactly one CreateDBSnapshot to fail: {outcomes}"
    assert failures[0]["code"] == "DBSnapshotAlreadyExists", failures[0]
    assert failures[0]["message"] == (
        f"Cannot create the snapshot because a snapshot with the identifier {snapshot_id} already exists."
    ), failures[0]

    ctx.on_cleanup(lambda: _delete_snapshot(rds, snapshot_id))
    _wait_for_snapshot_status(rds, snapshot_id, {"available"}, timeout_s=900, interval_s=15)

    matches = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"]
    assert len(matches) == 1, f"expected exactly one snapshot object for {snapshot_id}, found {len(matches)}"


def _capture(fn):
    from botocore.exceptions import ClientError

    try:
        return {"ok": True, "result": fn()}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"], "message": exc.response["Error"].get("Message")}


def _wait_for_instance_status(rds, instance_id, ok_statuses, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        last = resp["DBInstances"][0]
        if last["DBInstanceStatus"] in ok_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} never reached {ok_statuses} within {timeout_s}s; "
        f"last status={(last.get('DBInstanceStatus') if last else None)!r}"
    )


def _wait_for_snapshot_status(rds, snapshot_id, ok_statuses, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
        last = resp["DBSnapshots"][0]
        if last["Status"] in ok_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} never reached {ok_statuses} within {timeout_s}s; "
        f"last status={(last.get('Status') if last else None)!r}"
    )


def _delete_instance(rds, instance_id):
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
            return
        raise
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                return
            raise
        time.sleep(20)


def _delete_snapshot(rds, snapshot_id):
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBSnapshotNotFoundFault":
            return
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
