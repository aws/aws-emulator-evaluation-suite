"""modify-apply-immediately-false-pending-modified-values."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-apply-immediately-false-pending-modified-values"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_FROM_CLASS = "db.t3.micro"
_TO_CLASS = "db.t3.small"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
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
    """Poll a DB instance to 'available' and return its describe payload."""
    inst = _poll(
        lambda: _instance(rds, inst_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=timeout_s,
    )
    assert inst is not None, f"DB instance {inst_id} vanished while waiting for 'available'"
    assert inst["DBInstanceStatus"] == "available", (
        f"DB instance {inst_id} did not reach 'available' within {timeout_s}s; "
        f"last status {inst['DBInstanceStatus']!r}"
    )
    return inst


def _delete_instance(rds, inst_id):
    """Best-effort teardown: delete an instance with no final snapshot."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _pending(rds, inst_id):
    """The instance's PendingModifiedValues ({} when nothing is pending)."""
    inst = _instance(rds, inst_id)
    return (inst or {}).get("PendingModifiedValues") or {}


def _default_engine_version(rds, engine):
    """The engine's current default version, or None when the catalog is unavailable."""
    try:
        versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
            "DBEngineVersions", []
        )
    except ClientError:
        return None
    return versions[0]["EngineVersion"] if versions else None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance(ApplyImmediately=False) parks a class change in PendingModifiedValues and
    keeps the live class; a no-outage change (CopyTagsToSnapshot) applies at once, never pending;
    re-requesting the current class clears the pending entry.
    """
    rds = ctx.client("rds")
    version = _default_engine_version(rds, "postgres")

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    create = {
        "DBInstanceIdentifier": inst_id,
        "Engine": "postgres",
        "DBInstanceClass": _FROM_CLASS,
        "AllocatedStorage": 20,
        "MasterUsername": _USER,
        "MasterUserPassword": _PASS,
        "BackupRetentionPeriod": 0,
        "CopyTagsToSnapshot": False,
        "DeletionProtection": False,
        "Tags": _MANAGED_TAGS,
        "DBSubnetGroupName": _network_db_subnet_group(ctx, rds),
    }
    if version:
        create["EngineVersion"] = version
    rds.create_db_instance(**create)
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    inst = _wait_instance_available(rds, inst_id)
    assert inst["DBInstanceClass"] == _FROM_CLASS, (
        f"precondition: freshly created instance must be {_FROM_CLASS}, got "
        f"{inst['DBInstanceClass']!r}"
    )
    assert inst.get("CopyTagsToSnapshot") is False, (
        f"precondition: CopyTagsToSnapshot must start False, got {inst.get('CopyTagsToSnapshot')!r}"
    )
    assert not _pending(rds, inst_id), (
        f"a settled instance must have an empty PendingModifiedValues; got {_pending(rds, inst_id)!r}"
    )

    # An outage-causing change with ApplyImmediately=False.
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass=_TO_CLASS,
        ApplyImmediately=False,
    )
    pending = _poll(
        lambda: _pending(rds, inst_id),
        lambda p: p.get("DBInstanceClass") == _TO_CLASS,
        timeout_s=300,
        interval_s=10,
    )
    assert pending.get("DBInstanceClass") == _TO_CLASS, (
        "ModifyDBInstance(ApplyImmediately=False) must record the new class in "
        f"PendingModifiedValues.DBInstanceClass; got {pending!r}"
    )
    live = _instance(rds, inst_id)
    assert live["DBInstanceClass"] == _FROM_CLASS, (
        f"the live DBInstanceClass must still be {_FROM_CLASS} until the maintenance window; "
        f"got {live['DBInstanceClass']!r} — the emulator applied a deferred change immediately"
    )
    assert live["DBInstanceStatus"] == "available", (
        "a deferred class change must not start a resize: the instance must stay 'available', "
        f"got {live['DBInstanceStatus']!r}"
    )

    # Same call shape, no-outage attribute: applies immediately, never goes pending.
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id,
        CopyTagsToSnapshot=True,
        ApplyImmediately=False,
    )
    copy_tags = _poll(
        lambda: (_instance(rds, inst_id) or {}).get("CopyTagsToSnapshot"),
        lambda v: v is True,
        timeout_s=300,
        interval_s=10,
    )
    assert copy_tags is True, (
        "CopyTagsToSnapshot causes no outage, so RDS applies it even with "
        f"ApplyImmediately=False; the live value is still {copy_tags!r}"
    )
    pending = _pending(rds, inst_id)
    assert "CopyTagsToSnapshot" not in pending, (
        f"a no-outage attribute must not be parked in PendingModifiedValues; got {pending!r}"
    )
    assert pending.get("DBInstanceClass") == _TO_CLASS, (
        "the earlier deferred class change must survive an unrelated modify; got "
        f"{pending!r}"
    )

    # Withdrawing the change clears the pending entry, so the instance is never resized.
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass=_FROM_CLASS,
        ApplyImmediately=False,
    )
    pending = _poll(
        lambda: _pending(rds, inst_id),
        lambda p: "DBInstanceClass" not in p,
        timeout_s=600,
        interval_s=15,
    )
    assert "DBInstanceClass" not in pending, (
        "re-requesting the CURRENT class must drop the pending entry rather than leave a "
        f"no-op queued; PendingModifiedValues is still {pending!r}"
    )
    final = _instance(rds, inst_id)
    assert final["DBInstanceClass"] == _FROM_CLASS, (
        f"the instance must never have left {_FROM_CLASS}; got {final['DBInstanceClass']!r}"
    )
    assert final["DBInstanceStatus"] == "available", (
        f"instance must settle back to 'available' after withdrawing the pending change; "
        f"got {final['DBInstanceStatus']!r}"
    )


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
