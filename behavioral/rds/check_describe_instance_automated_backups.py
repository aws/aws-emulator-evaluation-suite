"""describe-instance-automated-backups."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-instance-automated-backups"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _instance(rds, ident):
    try:
        insts = rds.describe_db_instances(DBInstanceIdentifier=ident).get("DBInstances", [])
        return insts[0] if insts else None
    except ClientError:
        return None


def _mysql_instance_kwargs(ident):
    return dict(
        DBInstanceIdentifier=ident,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword=_make_password(),
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBInstanceAutomatedBackups: a real, running instance with backups enabled has an
    active automated-backup record describable by DBInstanceIdentifier. Error boundary: an unknown
    DBInstanceIdentifier rejects with DBInstanceAutomatedBackupNotFound.
    """
    rds = ctx.client("rds")
    ident = ctx.unique_name("sim2real-behav-dbi-")
    rds.create_db_instance(**_mysql_instance_kwargs(ident), DBSubnetGroupName=_network_db_subnet_group(ctx, rds))

    def _cleanup_delete():
        try:
            rds.delete_db_instance(DBInstanceIdentifier=ident, SkipFinalSnapshot=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DBInstanceNotFound":
                raise

    ctx.on_cleanup(_cleanup_delete)
    _poll_until(
        lambda: _instance(rds, ident),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} available",
    )

    def probe():
        resp = rds.describe_db_instance_automated_backups(DBInstanceIdentifier=ident)
        return resp.get("DBInstanceAutomatedBackups", [])

    backups = _poll_until(
        probe,
        lambda b: len(b) > 0,
        timeout_s=180,
        interval_s=5,
        description=f"automated backup record for instance {ident}",
    )
    assert backups[0]["DBInstanceIdentifier"] == ident, (
        f"expected automated backup for {ident!r}, got {backups[0].get('DBInstanceIdentifier')!r}"
    )
    assert backups[0]["Status"] == "active", (
        f"expected automated backup status 'active' for {ident!r}, got {backups[0].get('Status')!r}"
    )

    bogus_ident = ctx.unique_name("sim2real-behav-dbi-missing-")
    err = _rejection(
        lambda: rds.describe_db_instance_automated_backups(DBInstanceIdentifier=bogus_ident)
    )
    assert err.get("Code") == "DBInstanceAutomatedBackupNotFound", f"unexpected error: {err}"
    assert err.get("Message") == (
        f"DBInstanceAutomatedBackup for DBInstance {bogus_ident} not found."
    ), f"unexpected DBInstanceAutomatedBackupNotFound message: {err}"

    rds.delete_db_instance(DBInstanceIdentifier=ident, SkipFinalSnapshot=True)
    _poll_until(
        lambda: _instance(rds, ident),
        lambda i: i is None,
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} deleted",
    )

    def backups_after_delete():
        try:
            return probe()
        except ClientError:
            return None

    _poll_until(
        backups_after_delete,
        lambda b: b is None,
        timeout_s=180,
        interval_s=5,
        description=f"automated backups for deleted instance {ident} to disappear",
    )
    gone = _rejection(
        lambda: rds.describe_db_instance_automated_backups(DBInstanceIdentifier=ident)
    )
    assert gone.get("Code") == "DBInstanceAutomatedBackupNotFound", (
        f"expected automated backups to disappear once instance {ident} is gone "
        f"(default DeleteAutomatedBackups=True), got {gone}"
    )
    assert gone.get("Message") == f"DBInstanceAutomatedBackup for DBInstance {ident} not found.", (
        f"unexpected DBInstanceAutomatedBackupNotFound message after delete: {gone}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
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
