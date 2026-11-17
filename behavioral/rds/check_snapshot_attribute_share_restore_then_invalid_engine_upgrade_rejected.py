"""snapshot-attribute-share-restore-then-invalid-engine-upgrade-rejected."""
from __future__ import annotations

import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-attribute-share-restore-then-invalid-engine-upgrade-rejected"
GROUP = "snapshots"
SERVICES = ["rds"]

_SHARE_ACCOUNT = "111122223333"


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _error_code_and_message(fn):
    """Call ``fn`` and return its ``(Code, Message)``; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _instance(rds, ident):
    insts = rds.describe_db_instances(DBInstanceIdentifier=ident).get("DBInstances", [])
    return insts[0] if insts else None


def _snapshot(rds, snap_id):
    snaps = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id).get("DBSnapshots", [])
    return snaps[0] if snaps else None


def _restore_values(rds, snap_id):
    result = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap_id)["DBSnapshotAttributesResult"]
    assert result["DBSnapshotIdentifier"] == snap_id, (
        f"expected DescribeDBSnapshotAttributes to echo {snap_id!r}, got {result['DBSnapshotIdentifier']!r}"
    )
    restore_attr = next(a for a in result["DBSnapshotAttributes"] if a["AttributeName"] == "restore")
    return restore_attr["AttributeValues"]


def _parse_simple_version(v):
    m = re.fullmatch(r"(\d+)\.(\d+)", v)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _downgrade_target_version(rds, current_version):
    """A real postgres engine version strictly older than ``current_version``."""
    current = _parse_simple_version(current_version)
    assert current is not None, f"unexpected engine version format: {current_version!r}"
    offered = rds.describe_db_engine_versions(Engine="postgres")["DBEngineVersions"]
    older = [
        parsed for v in offered
        if (parsed := _parse_simple_version(v["EngineVersion"])) is not None and parsed < current
    ]
    assert older, f"no postgres engine version older than {current_version!r} is offered"
    major, minor = max(older)
    return f"{major}.{minor}"


def _create_subnet_group(ctx):
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-dbsg-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        "DBSubnetGroupNotFoundFault",
    ))
    return name


def _delete_instance_and_wait(rds, ident, timeout_s=1500.0, interval_s=15.0):
    """Delete the instance and wait until it is gone, so the subnet group teardown after it
    does not race an instance still "deleting"."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=ident, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=ident)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"instance {ident} was not deleted within {timeout_s}s")


def _teardown(undo, *not_found):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sharing a manual DB snapshot with another account and revoking it round-trips the
    restore attribute; modifying its engine version to an invalid upgrade target is refused
    with its exact error, leaving the snapshot's engine version and status unchanged.
    """
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    ident = ctx.unique_name("sim2real-behav-dbi-")
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
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, ident))
    instance = _poll_until(
        lambda: _instance(rds, ident),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=1500,
        interval_s=15,
        description=f"instance {ident} available",
    )
    original_engine_version = instance["EngineVersion"]

    snap_id = ctx.unique_name("sim2real-behav-snap-")
    rds.create_db_snapshot(
        DBInstanceIdentifier=ident,
        DBSnapshotIdentifier=snap_id,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(
        lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id),
        "DBSnapshotNotFound",
    ))
    snapshot = _poll_until(
        lambda: _snapshot(rds, snap_id),
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=1500,
        interval_s=15,
        description=f"snapshot {snap_id} available",
    )
    assert snapshot["EngineVersion"] == original_engine_version, (
        f"expected the snapshot's engine version to match the instance's "
        f"{original_engine_version!r}, got {snapshot['EngineVersion']!r}"
    )

    starting_values = _restore_values(rds, snap_id)
    assert starting_values == [], (
        f"a freshly created manual snapshot with no explicit shares must report an empty "
        f"restore AttributeValues, got {starting_values!r}"
    )

    add_result = rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier=snap_id,
        AttributeName="restore",
        ValuesToAdd=[_SHARE_ACCOUNT],
    )["DBSnapshotAttributesResult"]
    add_restore_attr = next(a for a in add_result["DBSnapshotAttributes"] if a["AttributeName"] == "restore")
    assert add_restore_attr["AttributeValues"] == [_SHARE_ACCOUNT], (
        f"expected ModifyDBSnapshotAttribute to list {_SHARE_ACCOUNT!r} under restore, "
        f"got {add_restore_attr['AttributeValues']!r}"
    )

    shared_values = _restore_values(rds, snap_id)
    assert shared_values == [_SHARE_ACCOUNT], (
        f"expected DescribeDBSnapshotAttributes to read back {_SHARE_ACCOUNT!r} under restore, "
        f"got {shared_values!r}"
    )

    remove_result = rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier=snap_id,
        AttributeName="restore",
        ValuesToRemove=[_SHARE_ACCOUNT],
    )["DBSnapshotAttributesResult"]
    remove_restore_attr = next(a for a in remove_result["DBSnapshotAttributes"] if a["AttributeName"] == "restore")
    assert remove_restore_attr["AttributeValues"] == [], (
        f"expected ModifyDBSnapshotAttribute to restore the original empty restore list, "
        f"got {remove_restore_attr['AttributeValues']!r}"
    )

    restored_values = _restore_values(rds, snap_id)
    assert restored_values == [], (
        f"expected DescribeDBSnapshotAttributes to read back an empty restore list after the "
        f"removal, got {restored_values!r}"
    )

    downgrade_target = _downgrade_target_version(rds, original_engine_version)
    code, message = _error_code_and_message(
        lambda: rds.modify_db_snapshot(DBSnapshotIdentifier=snap_id, EngineVersion=downgrade_target)
    )
    assert code == "InvalidParameterCombination", f"unexpected error code: {code!r}"
    expected_message = (
        f"You can't upgrade the DB snapshot from the engine version "
        f"{original_engine_version} to {downgrade_target}."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unaffected = _snapshot(rds, snap_id)
    assert unaffected["EngineVersion"] == original_engine_version, (
        f"a rejected ModifyDBSnapshot must leave the engine version at "
        f"{original_engine_version!r}, got {unaffected['EngineVersion']!r}"
    )
    assert unaffected["Status"] == "available", (
        f"a rejected ModifyDBSnapshot must leave the snapshot available, got {unaffected['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
