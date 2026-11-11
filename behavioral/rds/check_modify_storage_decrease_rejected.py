"""modify-storage-decrease-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-storage-decrease-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """ModifyDBInstance requesting a lower AllocatedStorage than current is rejected;
    storage can only grow, never shrink, via this API."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-modstor-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        StorageType="gp2",
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        DeletionProtection=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))

    _wait_for_instance_status(rds, db_id, "available", timeout_s=900)

    # Break exactly one thing: request a storage DECREASE.
    code, message = _error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=db_id, AllocatedStorage=10, ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code: {code!r}"
    expected = "Invalid storage size for engine name mysql and storage type gp2: 10"
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Effect absent: storage unchanged and no pending storage modification queued.
    inst = _describe_instance(rds, db_id)
    assert inst["AllocatedStorage"] == 20, f"storage was mutated: {inst['AllocatedStorage']}"
    pending = inst.get("PendingModifiedValues", {})
    assert "AllocatedStorage" not in pending, f"a storage decrease got queued: {pending}"
    assert inst["DBInstanceStatus"] == "available", (
        f"instance {db_id} left status {inst['DBInstanceStatus']!r} after the rejected shrink"
    )

    # Positive control: an INCREASE in the same file must be accepted. The terminal read is an
    # independent DescribeDBInstances call, not the ModifyDBInstance response itself, so this
    # cannot pass a target that merely echoes the mutating request back.
    rds.modify_db_instance(DBInstanceIdentifier=db_id, AllocatedStorage=30, ApplyImmediately=True)
    _wait_for_storage_accepted(rds, db_id, 30, timeout_s=60)


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_storage_accepted(rds: Any, db_id: str, target: int, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    inst = None
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        pending = inst.get("PendingModifiedValues", {}).get("AllocatedStorage")
        if inst["AllocatedStorage"] == target or pending == target:
            return
        time.sleep(5)
    raise AssertionError(
        f"storage increase to {target} was never reflected via an independent read for {db_id}; "
        f"last observed AllocatedStorage={inst and inst['AllocatedStorage']!r} "
        f"PendingModifiedValues={inst and inst.get('PendingModifiedValues')!r}"
    )


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFoundFault":
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
