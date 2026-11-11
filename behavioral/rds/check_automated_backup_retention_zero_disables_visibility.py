"""automated-backup-retention-zero-disables-visibility."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-backup-retention-zero-disables-visibility"
GROUP = "visibility-timeout-ttl"
SERVICES = ["rds"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-backupvis"},
    {"Key": "sim2real", "Value": "automated-backup-retention-zero-disables-visibility"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Setting BackupRetentionPeriod=0 on a running DB instance closes the automated-backup
    visibility window: the active DescribeDBInstanceAutomatedBackups entry for that instance
    disappears once the change applies, whereas it was visible while retention was > 0."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-backupvis-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        BackupRetentionPeriod=1,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)

    # With retention > 0, an active automated-backup entry is visible for this instance.
    active_before = _wait_active_backup(ctx, instance_id, expect_present=True, timeout_s=300)
    if active_before is None and _budget_spent(ctx):
        raise TimeoutError(f"active automated backup for {instance_id}: the run budget ended first; not graded")
    assert active_before is not None, "expected an active automated backup entry while retention > 0"

    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, BackupRetentionPeriod=0, ApplyImmediately=True
    )
    _wait_retention(ctx, instance_id, 0, timeout_s=300)

    # Visibility window closes: no active entry remains for this instance going forward.
    active_after = _wait_active_backup(ctx, instance_id, expect_present=False, timeout_s=300)
    if active_after is not None and _budget_spent(ctx):
        raise TimeoutError(f"no active automated backup for {instance_id}: the run budget ended first; not graded")
    assert active_after is None, (
        f"expected no active automated backup entry after retention=0, got {active_after!r}"
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


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_retention(ctx, instance_id, target_value, timeout_s=300, poll_s=2) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last.get("BackupRetentionPeriod") == target_value:
            return
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"instance {instance_id} BackupRetentionPeriod {target_value}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"instance {instance_id} BackupRetentionPeriod never reached {target_value}, "
        f"last observed {last and last.get('BackupRetentionPeriod')!r}"
    )


def _wait_active_backup(ctx, instance_id, expect_present, timeout_s=300, poll_s=2):
    """Poll DescribeDBInstanceAutomatedBackups until an 'active' entry for this instance is
    present (expect_present=True) or absent (expect_present=False). RDS raises
    DBInstanceAutomatedBackupNotFoundFault (rather than returning an empty list) when no
    automated-backup record exists yet for the instance at all -- treat that the same as
    "no active entry"."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_match = None
    while time.monotonic() < deadline:
        try:
            backups = rds.describe_db_instance_automated_backups(
                DBInstanceIdentifier=instance_id
            )["DBInstanceAutomatedBackups"]
        except rds.exceptions.DBInstanceAutomatedBackupNotFoundFault:
            backups = []
        active = [b for b in backups if b.get("Status") == "active"]
        last_match = active[0] if active else None
        if expect_present and last_match is not None:
            return last_match
        if not expect_present and last_match is None:
            return None
        time.sleep(poll_s)
    return last_match if expect_present else last_match


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
