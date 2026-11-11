"""master-username-case-preservation-round-trip."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "master-username-case-preservation-round-trip"
GROUP = "representation"
SERVICES = ["rds"]

_MASTER_USER = "Sim2RealAdminUser"
_MASTER_PASS = "Sim2RealPwd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A mixed-case admin user name supplied at CreateDBInstance is stored and returned with
    its original casing intact -- not normalized to all-lowercase."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-mucase-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    create_resp = rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))

    # The create response itself already reports the username -- assert its casing there too,
    # not just on a later describe.
    assert create_resp["DBInstance"]["MasterUsername"] == _MASTER_USER, (
        f"CreateDBInstance response mangled casing: {create_resp['DBInstance']['MasterUsername']!r}"
    )

    inst = _wait_for_instance_status(rds, db_id, "available", timeout_s=900)
    assert inst["MasterUsername"] == _MASTER_USER, (
        f"MasterUsername casing not preserved on describe: {inst['MasterUsername']!r} != {_MASTER_USER!r}"
    )


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return inst
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
