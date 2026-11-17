"""create-instance-admin-password-length-per-engine."""

from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-admin-password-length-per-engine"
GROUP = "errors"
SERVICES = ["rds"]

_ADMIN_USER = "sim2realadmin"
#: 42 printable-ASCII characters: one past MySQL's 41-character maximum, but inside
#: PostgreSQL's 8-128 range.
_PASSWORD_OVER_MYSQL_MAX = "Sim2Real1" + "A" * 33
#: 129 characters: one past PostgreSQL's 128-character maximum.
_PASSWORD_OVER_POSTGRES_MAX = "Sim2Real1" + "A" * 120
_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateDBInstance rejects an admin password over 41 characters for mysql and over 128 for
    postgres with InvalidParameterValue and creates nothing; a 42-character password is accepted
    for postgres."""
    rds = ctx.client("rds")
    subnet_group = _network_db_subnet_group(ctx, rds)

    mysql_id = ctx.unique_name("sim2real-pwlen-mysql-")
    # Registered before the create: an unexpected success must not leak the instance.
    ctx.on_cleanup(lambda: _delete_instance(rds, mysql_id))
    code, message = _create_rejected(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=mysql_id,
            Engine="mysql",
            DBInstanceClass="db.t3.micro",
            AllocatedStorage=20,
            MasterUsername=_ADMIN_USER,
            MasterUserPassword=_PASSWORD_OVER_MYSQL_MAX,
            BackupRetentionPeriod=0,
            Tags=_TAGS,
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterValue", (
        f"unexpected error code for a too-long mysql password: {code!r}"
    )
    expected_mysql_message = "The parameter MasterUserPassword is not a valid password because it is longer than 41 characters."
    assert message == expected_mysql_message, (
        f"expected message {expected_mysql_message!r}, got {message!r}"
    )
    not_found_mysql = _wait_for_not_found(ctx, rds, mysql_id, timeout_s=60)
    expected_nf_mysql = f"DBInstance {mysql_id} not found."
    assert not_found_mysql.get("Message") == expected_nf_mysql, (
        f"expected message {expected_nf_mysql!r}, got {not_found_mysql.get('Message')!r}"
    )

    pg_reject_id = ctx.unique_name("sim2real-pwlen-pgreject-")
    # Registered before the create: an unexpected success must not leak the instance.
    ctx.on_cleanup(lambda: _delete_instance(rds, pg_reject_id))
    code, message = _create_rejected(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=pg_reject_id,
            Engine="postgres",
            DBInstanceClass="db.t3.micro",
            AllocatedStorage=20,
            MasterUsername=_ADMIN_USER,
            MasterUserPassword=_PASSWORD_OVER_POSTGRES_MAX,
            BackupRetentionPeriod=0,
            Tags=_TAGS,
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterValue", (
        f"unexpected error code for a too-long postgres password: {code!r}"
    )
    expected_pg_message = "The parameter MasterUserPassword is not a valid password because it is longer than 128 characters."
    assert message == expected_pg_message, (
        f"expected message {expected_pg_message!r}, got {message!r}"
    )
    not_found_pg = _wait_for_not_found(ctx, rds, pg_reject_id, timeout_s=60)
    expected_nf_pg = f"DBInstance {pg_reject_id} not found."
    assert not_found_pg.get("Message") == expected_nf_pg, (
        f"expected message {expected_nf_pg!r}, got {not_found_pg.get('Message')!r}"
    )

    # Positive control: the same password that mysql refused, inside PostgreSQL's longer range.
    pg_accept_id = ctx.unique_name("sim2real-pwlen-pgaccept-")
    rds.create_db_instance(
        DBInstanceIdentifier=pg_accept_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=_PASSWORD_OVER_MYSQL_MAX,
        BackupRetentionPeriod=0,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, pg_accept_id))
    status = _wait_for_instance_status(ctx, rds, pg_accept_id, "available", timeout_s=1500)
    got = (status["MasterUsername"], status["AllocatedStorage"])
    assert got == (_ADMIN_USER, 20), (
        f"the accepted instance reads (admin user name, allocated storage) {got!r}, "
        f"expected {(_ADMIN_USER, 20)!r}"
    )

    rds.delete_db_instance(DBInstanceIdentifier=pg_accept_id, SkipFinalSnapshot=True)
    not_found_accept = _wait_for_not_found(ctx, rds, pg_accept_id, timeout_s=900)
    expected_nf_accept = f"DBInstance {pg_accept_id} not found."
    assert not_found_accept.get("Message") == expected_nf_accept, (
        f"expected message {expected_nf_accept!r}, got {not_found_accept.get('Message')!r}"
    )


def _create_rejected(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected CreateDBInstance to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_not_found(ctx: Any, rds: Any, db_id: str, *, timeout_s: float) -> dict[str, str]:
    """Bounded poll until DescribeDBInstances refuses db_id with DBInstanceNotFound; return that
    refusal's Error dict. Any other error propagates."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last: Any = None
    while time.monotonic() < deadline:
        try:
            last = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"]
        except ClientError as exc:
            if exc.response["Error"].get("Code") != "DBInstanceNotFound":
                raise
            return exc.response["Error"]
        time.sleep(5)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {db_id!r} going away: run budget ended first; not graded")
    raise AssertionError(
        f"instance {db_id!r} still not DBInstanceNotFound after {timeout_s}s; last describe: {last!r}"
    )


def _wait_for_instance_status(
    ctx: Any, rds: Any, db_id: str, status: str, *, timeout_s: float
) -> dict[str, Any]:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    current: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        current = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        if current["DBInstanceStatus"] == status:
            return current
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"DB instance {db_id} reaching {status!r}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"DB instance {db_id} never reached status={status!r} in {timeout_s}s; last: {current!r}"
    )


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
            raise


def _network_db_subnet_group(ctx: Any, client: Any) -> str:
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


def _delete_when_released(
    delete: Callable[[], Any],
    busy_codes: tuple[str, ...],
    gone_codes: tuple[str, ...],
    timeout_s: float = 1500.0,
    interval_s: float = 15.0,
) -> None:
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
