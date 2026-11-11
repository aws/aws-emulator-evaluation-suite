"""modify-apply-immediately-true-clears-a-prior-deferred-class-change."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-apply-immediately-true-clears-a-prior-deferred-class-change"
GROUP = "instance_lifecycle"
SERVICES = ["rds"]

_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_FROM_CLASS = "db.t3.micro"
_TO_CLASS = "db.t3.small"
_FROM_STORAGE = 20
_TO_STORAGE = 25
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
    """Delete an instance with no final snapshot; an instance already gone is done."""
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
    """ModifyDBInstance(ApplyImmediately=True) applies a class and a storage increase at once,
    superseding a class change an earlier ApplyImmediately=False call had left pending, and
    leaves PendingModifiedValues empty rather than parking either change.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ModifyInstance.Settings.html
    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Storage.html#USER_PIOPS.Autoscaling
    """
    rds = ctx.client("rds")
    version = _default_engine_version(rds, "postgres")

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    create = {
        "DBInstanceIdentifier": inst_id,
        "Engine": "postgres",
        "DBInstanceClass": _FROM_CLASS,
        "AllocatedStorage": _FROM_STORAGE,
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
    assert inst["AllocatedStorage"] == _FROM_STORAGE, (
        f"precondition: freshly created instance must hold {_FROM_STORAGE} GiB, got "
        f"{inst['AllocatedStorage']!r}"
    )
    assert not _pending(rds, inst_id), (
        f"a settled instance must have an empty PendingModifiedValues; got {_pending(rds, inst_id)!r}"
    )

    # Deferred branch: a class change with ApplyImmediately=False parks it, the live class stays.
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
        f"the live DBInstanceClass must still be {_FROM_CLASS} until applied; got "
        f"{live['DBInstanceClass']!r}"
    )

    # Immediate branch: the same class change, plus a storage increase, with ApplyImmediately=True
    # supersedes the deferred class change and applies both at once.
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass=_TO_CLASS,
        AllocatedStorage=_TO_STORAGE,
        ApplyImmediately=True,
    )
    final = _poll(
        lambda: _instance(rds, inst_id),
        lambda i: (i is not None and i.get("DBInstanceStatus") == "available"
                   and i.get("DBInstanceClass") == _TO_CLASS
                   and i.get("AllocatedStorage") == _TO_STORAGE),
        timeout_s=2100,
    )
    assert final is not None and final["DBInstanceStatus"] == "available", (
        f"instance {inst_id} did not settle back to 'available' after the immediate modify; "
        f"last status {final and final.get('DBInstanceStatus')!r}"
    )
    assert final["DBInstanceClass"] == _TO_CLASS, (
        f"ApplyImmediately=True must apply the class change at once; live class is "
        f"{final['DBInstanceClass']!r}, expected {_TO_CLASS!r}"
    )
    assert final["AllocatedStorage"] == _TO_STORAGE, (
        f"ApplyImmediately=True must apply the storage increase at once; live storage is "
        f"{final['AllocatedStorage']!r} GiB, expected {_TO_STORAGE!r}"
    )
    assert final.get("PendingModifiedValues") == {}, (
        "after an ApplyImmediately=True modify applies every requested change, "
        f"PendingModifiedValues must be empty; got {final.get('PendingModifiedValues')!r}"
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
