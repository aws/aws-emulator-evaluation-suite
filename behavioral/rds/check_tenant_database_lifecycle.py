"""tenant-database-lifecycle."""
from __future__ import annotations

import secrets
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tenant-database-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_ADMIN_PW = "S2r" + secrets.token_urlsafe(18)
_TENANT_PW = "S2t" + secrets.token_urlsafe(18)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On an oracle-se2-cdb instance, two tenant databases are created and both listed, the first is
    renamed with ModifyTenantDatabase, and deleting each is accepted and removes it."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    instance_id = ctx.unique_name("sim2real-behav-cdb-")
    try:
        # Use the default oracle-se2-cdb engine version (`DefaultOnly=True`).
        engine_version = rds.describe_db_engine_versions(
            Engine="oracle-se2-cdb", DefaultOnly=True
        )["DBEngineVersions"][0]["EngineVersion"]
        rds.create_db_instance(
            DBInstanceIdentifier=instance_id,

            Engine="oracle-se2-cdb",
            EngineVersion=engine_version,
            DBInstanceClass="db.m5.large",
            MasterUsername="simadmin",
            MasterUserPassword=_ADMIN_PW,
            # 100 GiB is the documented minimum allocated storage for the CDB (multi-tenant)
            # architecture. The multi-tenant (CDB) architecture requires automated backups
            # (BackupRetentionPeriod >= 1) -- ARCHIVELOG mode, which tenant database
            # create/delete depends on, is only configured when backups are on.
            AllocatedStorage=100,
            # gp3 (general purpose SSD) storage.
            StorageType="gp3",
            BackupRetentionPeriod=1,
            LicenseModel="license-included",
            DBSubnetGroupName=subnet_group,
            MultiTenant=True,
        )
    except ClientError as e:
        raise AssertionError(f"CreateDBInstance for a multi-tenant oracle-se2-cdb instance was refused: {e}")

    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))
    # An Oracle CDB instance takes 20-40 minutes to become available on real AWS; the rds
    # suite's per-check budget (5400 s) leaves room for that plus the tenant work below.
    _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=2700.0, interval_s=20.0)

    # CreateTenantDatabase requires TenantDBName shorter than 8 characters, and the
    # rename below appends one; Oracle reports the names upper-cased, so they are written that way.
    tenant_a = "S2RTA"
    tenant_b = "S2RTB"
    # Each CreateTenantDatabase puts the CDB instance into a modification of its own, and a second
    # create is refused until it is available again ("isn't in an available state"), so the two
    # tenants are created one after the other.
    for tenant in (tenant_a, tenant_b):
        rds.create_tenant_database(
            DBInstanceIdentifier=instance_id, TenantDBName=tenant, MasterUsername="tenantadmin", MasterUserPassword=_TENANT_PW
        )
        _wait_tenant_status(ctx, instance_id, tenant, {"available"}, timeout_s=900.0)
        _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=900.0, interval_s=20.0)

    described = rds.describe_tenant_databases(
        DBInstanceIdentifier=instance_id
    )["TenantDatabases"]
    names = {t["TenantDBName"] for t in described}
    assert {tenant_a, tenant_b} <= names, f"expected both tenants present, got {names!r}"

    rds.modify_tenant_database(DBInstanceIdentifier=instance_id, TenantDBName=tenant_a, NewTenantDBName=tenant_a + "X")
    tenant_a = tenant_a + "X"
    _wait_tenant_status(ctx, instance_id, tenant_a, {"available"}, timeout_s=900.0)
    # The rename, like a create, runs as a modification of the CDB instance; a tenant delete is
    # refused until the instance is available again.
    _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=900.0, interval_s=20.0)

    # The CDB keeps its default tenant (ORCL) alongside the two created here, so the second
    # tenant is not the instance's last one: real AWS deletes it like the first. Both deletes
    # pass SkipFinalSnapshot (or DeleteTenantDatabase demands a final snapshot name).
    rds.delete_tenant_database(DBInstanceIdentifier=instance_id, TenantDBName=tenant_a, SkipFinalSnapshot=True)
    _wait_tenant_gone(ctx, instance_id, tenant_a, timeout_s=900.0)
    _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=900.0, interval_s=20.0)

    rds.delete_tenant_database(DBInstanceIdentifier=instance_id, TenantDBName=tenant_b, SkipFinalSnapshot=True)
    _wait_tenant_gone(ctx, instance_id, tenant_b, timeout_s=900.0)


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_subnet_group(ctx) -> str:
    """A DB subnet group over the run's shared network, deleted once the instance is gone."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=ctx.network().subnet_ids,
    )

    def _delete() -> None:
        deadline = time.monotonic() + 600.0
        while True:
            try:
                rds.delete_db_subnet_group(DBSubnetGroupName=name)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "DBSubnetGroupNotFoundFault":
                    return
                if code not in ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState") or time.monotonic() >= deadline:
                    raise
            time.sleep(15.0)

    ctx.on_cleanup(_delete)
    return name


def _delete_instance(rds, instance_id: str, timeout_s: float = 1500.0) -> None:
    """Delete the CDB instance and wait until it is gone, so its subnet group can follow."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFound":
            return
        if e.response["Error"]["Code"] != "InvalidDBInstanceState":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            inst = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        if inst["DBInstanceStatus"] == "available":
            rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
        time.sleep(20.0)
    raise RuntimeError(f"DB instance {instance_id} still exists {timeout_s}s after DeleteDBInstance")


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 600.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_tenant_status(ctx, instance_id: str, tenant_name: str, statuses: set[str], timeout_s: float = 900.0, interval_s: float = 8.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        tenants = rds.describe_tenant_databases(
            DBInstanceIdentifier=instance_id, Filters=[{"Name": "tenant-db-name", "Values": [tenant_name]}]
        )["TenantDatabases"]
        assert len(tenants) <= 1, f"expected at most one tenant {tenant_name!r}, got {tenants!r}"
        # A tenant being created or renamed is listed under its new name a little later.
        return tenants[0] if tenants else None

    return _poll_until(
        probe, lambda t: t is not None and t["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s
    )


def _wait_tenant_gone(ctx, instance_id: str, tenant_name: str, timeout_s: float = 600.0, interval_s: float = 8.0) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tenants = rds.describe_tenant_databases(
            DBInstanceIdentifier=instance_id, Filters=[{"Name": "tenant-db-name", "Values": [tenant_name]}]
        )["TenantDatabases"]
        if not tenants:
            return
        time.sleep(interval_s)
    raise AssertionError(f"tenant database {tenant_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
