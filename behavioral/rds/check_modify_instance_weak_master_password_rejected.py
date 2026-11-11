"""modify-instance-weak-master-password-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-weak-master-password-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"
_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """ModifyDBInstance with an admin password that fails RDS's password-length
    requirement (too short) is rejected, and the stored credential is left unchanged --
    no password rotation is silently queued."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-weakpw-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    _wait_for_instance_status(rds, db_id, "available", timeout_s=900)

    # Break exactly one thing: a too-short password (RDS for PostgreSQL requires >= 8
    # printable-ASCII characters for the admin password).
    code, message = _error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=db_id, MasterUserPassword="weak1", ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code: {code!r}"
    expected = (
        "The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters."
    )
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Effect absent: no password rotation queued, instance still 'available'.
    inst = _describe_instance(rds, db_id)
    assert inst["DBInstanceStatus"] == "available"
    pending = inst.get("PendingModifiedValues", {})
    assert "MasterUserPassword" not in pending, f"a weak password rotation got queued: {pending}"

    # Positive control: a password meeting the length requirement is accepted and actually
    # settles -- proven via an independent DescribeDBInstances read (not the ModifyDBInstance
    # response). RDS does not flip DBInstanceStatus away from 'available' for a password-only
    # change, so PendingModifiedValues clearing -- not DBInstanceStatus -- is the observable
    # convergence signal.
    rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        MasterUserPassword="Sim2RealNewPwd456",
        ApplyImmediately=True,
    )
    settled = _wait_for_pending_cleared(rds, db_id, "MasterUserPassword", timeout_s=600)
    assert settled["DBInstanceStatus"] == "available", (
        f"instance was not 'available' once the accepted password change cleared as applied: "
        f"{settled['DBInstanceStatus']!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call was expected to be REJECTED but succeeded, returning {resp!r}"
    )


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _wait_for_pending_cleared(
    rds: Any, db_id: str, field: str, *, timeout_s: float
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while True:
        inst = _describe_instance(rds, db_id)
        pending = inst.get("PendingModifiedValues", {})
        if field not in pending:
            return inst
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DB instance {db_id} still shows {field!r} pending after {timeout_s}s: {pending}"
            )
        time.sleep(2)


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
