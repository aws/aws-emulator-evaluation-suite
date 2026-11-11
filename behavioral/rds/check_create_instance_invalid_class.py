"""create-instance-invalid-class."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-invalid-class"
GROUP = 'errors'
SERVICES = ['rds']

_MASTER_USER = "sim2real"
_MASTER_PASS = "Sim2Real#Pass99"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance with a nonexistent DBInstanceClass value is rejected
    synchronously with a specific error code and mints nothing; the identical
    request with a real instance class is accepted and reaches 'available'."""
    rds = ctx.client("rds")
    bad_id = ctx.unique_name("sim2real-behav-badclass-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    code, message = _create_rejected(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=bad_id,
            Engine="mysql",
            DBInstanceClass="db.sim2real.bogus",
            AllocatedStorage=20,
            MasterUsername=_MASTER_USER,
            MasterUserPassword=_MASTER_PASS,
            Tags=_MANAGED_TAGS,
            DBSubnetGroupName=subnet_group,
        )
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, bad_id))  # safety net if creation was not rejected
    assert code == "InvalidParameterValue", f"unexpected error code for bogus instance class: {code!r}"
    expected = "Invalid DB Instance class: db.sim2real.bogus"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected identifier must not exist at all, not even a failed record.
    not_found = _wait_for_not_found(rds, bad_id, timeout_s=60)
    expected_nf = f"DBInstance {bad_id} not found."
    assert not_found.get("Message") == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: the identical request with a real instance class is accepted.
    good_id = ctx.unique_name("sim2real-behav-goodclass-")
    rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        BackupRetentionPeriod=0,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, good_id))
    _wait_for_instance_status(rds, good_id, "available", timeout_s=900)


def _create_rejected(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected CreateDBInstance to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_not_found(rds: Any, db_id: str, *, timeout_s: float) -> dict[str, str]:
    """Bounded poll until DescribeDBInstances refuses db_id with DBInstanceNotFound; return that
    refusal's Error dict."""
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            last = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"]
        except ClientError as exc:
            last = exc.response["Error"]
            if last.get("Code") == "DBInstanceNotFound":
                return last
        time.sleep(5)
    raise AssertionError(
        f"instance {db_id!r} still not DBInstanceNotFound after {timeout_s}s; last describe: {last!r}"
    )


def _instance_status(rds: Any, db_id: str) -> str | None:
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"]
    except ClientError:
        return None


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        current = _instance_status(rds, db_id)
        if current == status:
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
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
