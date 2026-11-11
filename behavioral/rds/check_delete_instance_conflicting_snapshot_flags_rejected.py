"""delete-instance-conflicting-snapshot-flags-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-instance-conflicting-snapshot-flags-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBInstance called with SkipFinalSnapshot=True and a FinalDBSnapshotIdentifier set at
    the same time must be rejected as a conflicting combination -- not silently take a snapshot
    (ignoring skip) nor silently skip the identifier and delete anyway."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-delflags-")
    password = "S2r" + secrets.token_hex(10)

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, db_id))

    _poll_until(
        lambda: _describe_instance(rds, db_id),
        lambda inst: inst is not None and inst["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=20,
    )

    snap_id = ctx.unique_name("sim2real-rds-delflags-snap-")

    # Break exactly one thing: ask to both skip the final snapshot AND name one.
    code, msg = _client_error(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id,
            SkipFinalSnapshot=True,
            FinalDBSnapshotIdentifier=snap_id,
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    assert msg == "Only one of SkipFinalSnapshot and FinalDBSnapshotIdentifier can be specified", msg

    # Effect absent: the instance is still there and available, and no snapshot was created.
    inst = _describe_instance(rds, db_id)
    assert inst is not None and inst["DBInstanceStatus"] == "available", (
        f"instance should not have been deleted by a rejected request, observed: {inst!r}"
    )
    snap_code, snap_msg = _client_error(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)
    )
    assert snap_code == "DBSnapshotNotFound", (
        f"a rejected delete must not have created snapshot {snap_id!r}, got code {snap_code!r}"
    )
    assert snap_msg == f"DBSnapshot not found: {snap_id}", snap_msg

    # Positive control: the same delete request, minus the conflicting snapshot identifier,
    # succeeds and actually deletes the instance. This also serves as this check's teardown.
    rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    _poll_until(
        lambda: _describe_instance(rds, db_id),
        lambda inst: inst is None,
        timeout_s=1200,
        interval_s=20,
    )


def _client_error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _describe_instance(rds, db_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _safe_delete_instance(ctx, db_id) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
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
