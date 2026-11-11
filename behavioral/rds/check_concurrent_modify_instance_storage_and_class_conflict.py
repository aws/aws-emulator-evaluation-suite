"""concurrent-modify-instance-storage-and-class-conflict."""
from __future__ import annotations

import secrets
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-modify-instance-storage-and-class-conflict"
GROUP = "concurrency"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": "concurrent-modify-instance-storage-class"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent ModifyDBInstance calls (storage vs instance class) on one instance serialize: the final
    DescribeDBInstances reflects each successful call exactly and leaves a failed call's field untouched."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-conc-")
    original_class = "db.t3.micro"
    original_storage = 20
    new_class = "db.t3.small"
    new_storage = 30

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass=original_class,
        Engine="mysql",
        MasterUsername="sim2real",
        MasterUserPassword="S2r" + secrets.token_urlsafe(18),
        AllocatedStorage=original_storage,
        StorageType="gp2",
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))
    _wait_for_instance_status(rds, instance_id, {"available"}, timeout_s=1800, interval_s=20)

    def _modify_storage():
        return rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, AllocatedStorage=new_storage, ApplyImmediately=True
        )

    def _modify_class():
        return rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, DBInstanceClass=new_class, ApplyImmediately=True
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_storage = pool.submit(lambda: _capture(_modify_storage))
        fut_class = pool.submit(lambda: _capture(_modify_class))
        storage_outcome = fut_storage.result()
        class_outcome = fut_class.result()

    assert storage_outcome["ok"] or class_outcome["ok"], (
        f"at least one of the two concurrent ModifyDBInstance calls must succeed: "
        f"{storage_outcome}, {class_outcome}"
    )
    if not storage_outcome["ok"]:
        # The wire code is InvalidDBInstanceState (InvalidDBInstanceStateFault is only the
        # SDK's exception class name), as real AWS answered the losing leg.
        assert storage_outcome["code"] == "InvalidDBInstanceState", storage_outcome
    if not class_outcome["ok"]:
        assert class_outcome["code"] == "InvalidDBInstanceState", class_outcome

    final = _wait_for_instance_status(
        rds, instance_id, {"available", "storage-optimization"}, timeout_s=1800, interval_s=20
    )
    final_storage = final["AllocatedStorage"]
    final_class = final["DBInstanceClass"]
    pending = final.get("PendingModifiedValues") or {}
    pending_storage = pending.get("AllocatedStorage")
    pending_class = pending.get("DBInstanceClass")

    # A storage-size increase is accepted immediately (AllocatedStorage moves into
    # PendingModifiedValues) but the actual EBS resize can run well past the instance
    # reporting "available" again, so the applied value is not yet reflected in the
    # top-level field. Whichever leg won the race must show up as EITHER already
    # applied OR correctly queued -- never silently dropped nor smuggled into the
    # other field.
    if storage_outcome["ok"]:
        assert new_storage in (final_storage, pending_storage), (
            f"accepted storage change not reflected: applied={final_storage} pending={pending_storage}"
        )
    else:
        assert final_storage == original_storage and pending_storage is None, (
            f"rejected storage change leaked through: applied={final_storage} pending={pending_storage}"
        )

    if class_outcome["ok"]:
        assert new_class in (final_class, pending_class), (
            f"accepted class change not reflected: applied={final_class} pending={pending_class}"
        )
    else:
        assert final_class == original_class and pending_class is None, (
            f"rejected class change leaked through: applied={final_class} pending={pending_class}"
        )


def _capture(fn):
    from botocore.exceptions import ClientError

    try:
        return {"ok": True, "result": fn()}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"]}


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


def _delete_instance(rds, instance_id):
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return
        raise
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(20)
    raise AssertionError(f"DB instance {instance_id} still exists 1800s after DeleteDBInstance")


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
