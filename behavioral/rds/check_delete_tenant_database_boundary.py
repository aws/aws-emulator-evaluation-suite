"""delete-tenant-database-boundary."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-tenant-database-boundary"
GROUP = 'tenant_databases'
SERVICES = ['rds']

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"


def _client_error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTenantDatabase fails DBInstanceNotFound for a missing instance and
    InvalidParameterCombination on a non-CDB instance, which then lists no tenant databases.
    """
    rds = ctx.client("rds")

    bogus_id = ctx.unique_name("sim2real-behav-dbi-missing-")
    missing_code, missing_message = _client_error(
        lambda: rds.delete_tenant_database(
            DBInstanceIdentifier=bogus_id, TenantDBName="tenant1"
        )
    )
    assert missing_code == ERR_DB_INSTANCE_NOT_FOUND, (
        f"unexpected error code for a nonexistent instance: {missing_code}"
    )
    assert missing_message == f"DBInstance not found: {bogus_id}", missing_message

    db_id = ctx.unique_name("sim2real-behav-nocdb-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    instance = _wait_for_instance_status(rds, db_id, "available", timeout_s=900)
    dbi_resource_id = instance["DbiResourceId"]

    wrong_arch_code, wrong_arch_message = _client_error(
        lambda: rds.delete_tenant_database(DBInstanceIdentifier=db_id, TenantDBName="tenant1")
    )
    assert wrong_arch_code == "InvalidParameterCombination", (
        f"expected a rejection distinct from not-found on a real, non-CDB instance, "
        f"got {wrong_arch_code!r}"
    )
    assert wrong_arch_message == (
        f"The DeleteTenantDatabase operation isn't supported for DB instance {db_id}."
    ), wrong_arch_message

    # DescribeTenantDatabases recognizes only dbi-resource-id, tenant-db-name and
    # tenant-database-resource-id; any other filter name fails InvalidParameterValue.
    tenants = rds.describe_tenant_databases(
        Filters=[{"Name": "dbi-resource-id", "Values": [dbi_resource_id]}]
    )["TenantDatabases"]
    assert tenants == [], f"expected no tenant databases on a non-CDB instance, got {tenants!r}"


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
        if exc.response["Error"]["Code"] not in ("DBInstanceNotFound", "InvalidDBInstanceState"):
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
