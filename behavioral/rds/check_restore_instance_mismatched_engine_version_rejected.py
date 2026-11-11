"""restore-instance-mismatched-engine-version-rejected."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-instance-mismatched-engine-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Restoring a MySQL snapshot under the incompatible postgres Engine is rejected with no
    instance created, while restoring under the snapshot's own engine succeeds."""
    rds = ctx.client("rds")
    source_id = ctx.unique_name("sim2real-rds-src-")
    snapshot_id = ctx.unique_name("sim2real-rds-snap-")
    bad_restore_id = ctx.unique_name("sim2real-rds-badres-")
    good_restore_id = ctx.unique_name("sim2real-rds-goodres-")
    password = _rds_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=source_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="sim2real",
        MasterUserPassword=password,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        MultiAZ=False,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )

    def _cleanup_source():
        try:
            _wait_for_instance_status(rds, source_id, {"available"}, timeout_s=900, interval_s=2)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        except AssertionError:
            pass  # not settled: the delete below still runs and raises if it is refused
        try:
            rds.delete_db_instance(DBInstanceIdentifier=source_id, SkipFinalSnapshot=True)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        except ClientError as last:
            raise RuntimeError(f"db instance {source_id} was not deleted: {last!r}") from last

    ctx.on_cleanup(_cleanup_source)

    _wait_for_instance_status(rds, source_id, {"available"}, timeout_s=_budget_s(ctx, 900), interval_s=2, ctx=ctx)

    rds.create_db_snapshot(
        DBSnapshotIdentifier=snapshot_id,
        DBInstanceIdentifier=source_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snapshot_id))
    _wait_for_snapshot_status(rds, snapshot_id, {"available"}, timeout_s=_budget_s(ctx, 900), interval_s=2, ctx=ctx)

    # --- break exactly one thing: restore under a wholly incompatible engine ---
    # Restore has no EngineVersion parameter; Engine is the only compatibility knob it exposes.
    code, message = _error(
        lambda: rds.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=bad_restore_id,
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    expected = "Requested DBSnapshot and Engine are incompatible."
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    try:
        rds.describe_db_instances(DBInstanceIdentifier=bad_restore_id)
        raise AssertionError("the mismatched-engine restore created an instance anyway")
    except rds.exceptions.DBInstanceNotFoundFault:
        pass

    # --- positive control: restoring under the snapshot's own (compatible) engine succeeds ---
    rds.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=good_restore_id,
        DBSnapshotIdentifier=snapshot_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )

    def _cleanup_restore():
        try:
            _wait_for_instance_status(rds, good_restore_id, {"available"}, timeout_s=900, interval_s=2)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        except AssertionError:
            pass  # not settled: the delete below still runs and raises if it is refused
        try:
            rds.delete_db_instance(DBInstanceIdentifier=good_restore_id, SkipFinalSnapshot=True)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        except ClientError as last:
            raise RuntimeError(f"db instance {good_restore_id} was not deleted: {last!r}") from last

    ctx.on_cleanup(_cleanup_restore)

    created = _wait_for_instance_status(rds, good_restore_id, {"available"}, timeout_s=_budget_s(ctx, 1500), interval_s=2, ctx=ctx)
    assert created["Engine"] == "mysql", f"expected the restore to run mysql, got {created['Engine']!r}"


def _rds_password() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=24)) + "9Aa"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, so
    accepting a call AWS refuses is reported as such rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s (last={last!r})")


def _wait_for_instance_status(rds, instance_id, target_statuses, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    def _probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(
        _probe, lambda i: i["DBInstanceStatus"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s, ctx=ctx
    )


def _wait_for_snapshot_status(rds, snapshot_id, target_statuses, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    def _probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]

    return _poll_until(
        _probe, lambda s: s["Status"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s, ctx=ctx
    )


def _delete_snapshot(rds, snapshot_id) -> None:
    try:
        _wait_for_snapshot_status(rds, snapshot_id, {"available"}, timeout_s=900, interval_s=2)
    except rds.exceptions.DBSnapshotNotFoundFault:
        return
    except AssertionError:
        pass  # not settled: the delete below still runs and raises if it is refused
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except rds.exceptions.DBSnapshotNotFoundFault:
        return
    except ClientError as last:
        raise RuntimeError(f"db snapshot {snapshot_id} was not deleted: {last!r}") from last


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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

