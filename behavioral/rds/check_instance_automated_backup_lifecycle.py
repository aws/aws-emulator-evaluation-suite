"""instance-automated-backup-lifecycle."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags
import secrets

CHECK = "instance-automated-backup-lifecycle"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

ERR_INSTANCE_AUTOMATED_BACKUP_NOT_FOUND = "DBInstanceAutomatedBackupNotFound"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_instance(rds, ident):
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=ident)
        insts = resp.get("DBInstances", [])
        return insts[0] if insts else None
    except ClientError:
        return None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an instance with DeleteAutomatedBackups=False leaves a describable retained backup,
    which DeleteDBInstanceAutomatedBackup then removes; an unknown DbiResourceId is rejected with
    DBInstanceAutomatedBackupNotFound."""
    rds = ctx.client("rds")
    ident = ctx.unique_name("sim2real-behav-dbi-")
    rds.create_db_instance(
        DBInstanceIdentifier=ident,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=ident, SkipFinalSnapshot=True, DeleteAutomatedBackups=True), "DBInstanceNotFound"))
    inst = _poll_until(
        lambda: _describe_instance(rds, ident),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} available",
    )
    resource_id = inst["DbiResourceId"]

    rds.delete_db_instance(
        DBInstanceIdentifier=ident, SkipFinalSnapshot=True, DeleteAutomatedBackups=False
    )
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: rds.delete_db_instance_automated_backup(DbiResourceId=resource_id), "DBInstanceAutomatedBackupNotFound")
    )
    _poll_until(
        lambda: _describe_instance(rds, ident),
        lambda i: i is None,
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} deleted",
    )

    def probe_backup():
        try:
            resp = rds.describe_db_instance_automated_backups(DbiResourceId=resource_id)
        except ClientError:
            return None
        backups = resp.get("DBInstanceAutomatedBackups", [])
        return backups[0] if backups else None

    backup = _poll_until(
        probe_backup,
        lambda b: b is not None,
        timeout_s=120,
        interval_s=5,
        description=f"retained automated backup for {resource_id}",
    )
    assert backup["DBInstanceIdentifier"] == ident, (
        f"expected retained backup DBInstanceIdentifier {ident!r}, got {backup['DBInstanceIdentifier']!r}"
    )

    rds.delete_db_instance_automated_backup(DbiResourceId=resource_id)
    _poll_until(
        probe_backup,
        lambda b: b is None,
        timeout_s=120,
        interval_s=5,
        description=f"automated backup {resource_id} deleted",
    )

    bogus_resource_id = "db-" + uuid.uuid4().hex[:26].upper()
    code, message = _error_code(
        lambda: rds.delete_db_instance_automated_backup(DbiResourceId=bogus_resource_id)
    )
    assert code == ERR_INSTANCE_AUTOMATED_BACKUP_NOT_FOUND, f"unexpected error code: {code}"
    assert message == f"Automated backups could not be found for: {bogus_resource_id}", message


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
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.
    The 1500 s default window fits within the suite's 1800 s teardown budget."""
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


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
