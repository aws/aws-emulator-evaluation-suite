"""decrease-allocated-storage-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decrease-allocated-storage-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance with AllocatedStorage below the current size is rejected rather than shrinking
    the volume, while an unrelated modification of the same instance succeeds."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-storage-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    instance = _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)
    assert instance["AllocatedStorage"] == 20, (
        f"expected AllocatedStorage=20 after create, got {instance['AllocatedStorage']!r}"
    )

    code, message = _error_code(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, AllocatedStorage=10, ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code {code!r}"
    assert message == (
        f"Invalid storage size for engine name postgres and storage type {instance['StorageType']}: 10"
    ), f"unexpected message {message!r}"

    # Effect absent: storage must still be the original 20 GiB, not silently truncated, and no
    # shrink must be queued as a pending modification either.
    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["AllocatedStorage"] == 20, (
        f"AllocatedStorage changed to {instance['AllocatedStorage']} despite the rejected shrink"
    )
    pending = instance.get("PendingModifiedValues", {})
    assert "AllocatedStorage" not in pending, f"a storage shrink got queued as pending: {pending}"

    # Positive control (same file): a sibling, unrelated modification on the same instance still
    # succeeds -- the instance is not simply un-modifiable altogether.
    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, BackupRetentionPeriod=3, ApplyImmediately=True
    )
    _wait_backup_retention(ctx, instance_id, 3, timeout_s=180)


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_backup_retention(ctx, instance_id, target_value, timeout_s=180, poll_s=10) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["BackupRetentionPeriod"] == target_value:
            return
        time.sleep(poll_s)
    raise AssertionError(
        f"BackupRetentionPeriod on {instance_id} never reached {target_value}, last observed "
        f"{last and last.get('BackupRetentionPeriod')!r}"
    )


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
