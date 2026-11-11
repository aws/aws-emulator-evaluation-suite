"""master-username-length-boundary-postgres."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "master-username-length-boundary-postgres"
GROUP = "representation"
SERVICES = ["rds"]

# 26 characters -- past the 16-character ceiling MySQL enforces, but postgres accepts it (and
# stores/returns it) with no shortening or rejection.
_LONG_BUT_VALID_USER = "application_db_admin_user"
# 64 characters -- one past what PostgreSQL's rolname accepts (63, NAMEDATALEN-1).
_TOO_LONG_USER = "a" + "b" * 63
_PASS = "Sim2RealPwd99"


def _error(fn) -> tuple[str, str]:
    """Invoke fn(); return the AWS (error code, message), or raise if it unexpectedly succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    inst = _describe_instance(rds, db_id)
    while inst["DBInstanceStatus"] != status:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DB instance {db_id!r} never reached status={status!r} within {timeout_s}s; "
                f"last status={inst['DBInstanceStatus']!r}"
            )
        time.sleep(2)
        inst = _describe_instance(rds, db_id)
    return inst


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFoundFault":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """On postgres a 26-character admin user name (past MySQL's 16-character ceiling) is accepted
    and round-trips exactly, while a 64-character one (past PostgreSQL's 63) is refused by
    CreateDBInstance: the length limit follows the engine's identifier rules."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-mulen-")
    rejected_id = ctx.unique_name("sim2real-mulen-rej-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    create_resp = rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_LONG_BUT_VALID_USER,
        MasterUserPassword=_PASS,
        AllocatedStorage=10,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "master-username-length-boundary-postgres"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))

    assert create_resp["DBInstance"]["MasterUsername"] == _LONG_BUT_VALID_USER, (
        f"CreateDBInstance response: expected MasterUsername {_LONG_BUT_VALID_USER!r} "
        f"(len={len(_LONG_BUT_VALID_USER)}), got {create_resp['DBInstance']['MasterUsername']!r}"
    )

    described = _wait_for_status(rds, db_id, "available", timeout_s=900)
    assert described["MasterUsername"] == _LONG_BUT_VALID_USER, (
        f"DescribeDBInstances: expected MasterUsername {_LONG_BUT_VALID_USER!r}, got "
        f"{described['MasterUsername']!r} -- a 26-character postgres username must not be "
        f"truncated or otherwise mangled"
    )

    # Break exactly one thing: the SAME engine, a username one character past its own ceiling.
    create_err = _error(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=rejected_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername=_TOO_LONG_USER,
            MasterUserPassword=_PASS,
            AllocatedStorage=10,
            BackupRetentionPeriod=0,
            PubliclyAccessible=False,
            Tags=[{"Key": "sim2real", "Value": "master-username-length-boundary-postgres"}],
            DBSubnetGroupName=subnet_group,
        )
    )
    # Effect absent: the rejected identifier never became an instance.
    describe_err = _error(lambda: rds.describe_db_instances(DBInstanceIdentifier=rejected_id))
    expected_create = ("InvalidParameterValue", "Invalid master user name")
    assert create_err == expected_create, (
        f"a {len(_TOO_LONG_USER)}-character MasterUsername: expected {expected_create!r}, got "
        f"{create_err!r} (DescribeDBInstances then answered {describe_err!r})"
    )
    expected_describe = ("DBInstanceNotFound", f"DBInstance {rejected_id} not found.")
    assert describe_err == expected_describe, (
        f"the never-created {rejected_id!r}: expected {expected_describe!r}, got {describe_err!r}"
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
