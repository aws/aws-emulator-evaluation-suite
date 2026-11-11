"""automated-backup-retention-window-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "automated-backup-retention-window-enforced"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a non-zero BackupRetentionPeriod the instance has an active automated backup; setting
    it to 0 with ModifyDBInstance makes RDS delete that backup by itself (polled until gone), as
    documented."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rdsbkp-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="s2radmin",
        MasterUserPassword=_admin_password(),
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        StorageType="gp2",
        Tags=[{"Key": "sim2real", "Value": "automated-backup-retention-window-enforced"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))

    desc = _wait_for_instance_status(rds, instance_id, "available", timeout_s=900)
    assert desc is not None and desc["DBInstanceStatus"] == "available", (
        f"instance {instance_id!r} never reached 'available' within 900s "
        f"(last status={desc['DBInstanceStatus'] if desc else None!r})"
    )
    assert desc["BackupRetentionPeriod"] == 1, (
        f"instance {instance_id!r} BackupRetentionPeriod={desc['BackupRetentionPeriod']!r}, "
        f"expected 1 (as requested at creation)"
    )

    # While retention is non-zero, an 'active' automated-backup record must exist for this
    # instance -- the baseline this check will observe being purged below.
    active_backups = _wait_for_active_backups(rds, instance_id, timeout_s=300)
    assert active_backups, (
        f"expected an 'active' DBInstanceAutomatedBackup for {instance_id!r} while "
        f"BackupRetentionPeriod=1, found none"
    )

    # --- collapse the retention window to zero: no explicit delete-backup call is made ---
    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id, BackupRetentionPeriod=0, ApplyImmediately=True
    )
    desc_disabled = _wait_for_backup_retention(rds, instance_id, want=0, timeout_s=180)
    assert desc_disabled["BackupRetentionPeriod"] == 0, (
        f"instance {instance_id!r} BackupRetentionPeriod never reached 0 within 180s"
    )

    # The service purges the automated backup on its own -- confirm the active record is gone.
    remaining_active = _wait_for_no_active_backups(rds, instance_id, timeout_s=300)
    assert remaining_active == [], (
        f"expected the automated backup to be purged automatically after disabling retention, "
        f"still found active records: {remaining_active!r}"
    )


def _admin_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _wait_for_instance_status(rds, instance_id: str, want: str, timeout_s: float) -> dict | None:
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if desc["DBInstanceStatus"] == want:
            return desc
        time.sleep(2)
    return desc


def _wait_for_backup_retention(rds, instance_id: str, want: int, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    while time.monotonic() < deadline:
        desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if desc["BackupRetentionPeriod"] == want:
            return desc
        time.sleep(5)
    return desc


def _active_backups(rds, instance_id: str) -> list[dict]:
    from botocore.exceptions import ClientError

    # Real AWS raises DBInstanceAutomatedBackupNotFoundFault (rather than returning an
    # empty list) when no automated-backup record exists yet for this identifier -- e.g.
    # right after creation, or after the record has been purged. Treat that as "no active
    # backups" rather than letting it propagate.
    try:
        backups = rds.describe_db_instance_automated_backups(DBInstanceIdentifier=instance_id)[
            "DBInstanceAutomatedBackups"
        ]
    except ClientError as exc:
        # The exception class is named ...NotFoundFault, but the wire-level Error.Code some
        # accounts/regions return omits the "Fault" suffix -- check both spellings.
        code = exc.response["Error"]["Code"]
        if code in ("DBInstanceAutomatedBackupNotFoundFault", "DBInstanceAutomatedBackupNotFound"):
            return []
        raise
    return [b for b in backups if b["Status"] == "active"]


def _wait_for_active_backups(rds, instance_id: str, timeout_s: float) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    active: list[dict] = []
    while time.monotonic() < deadline:
        active = _active_backups(rds, instance_id)
        if active:
            return active
        time.sleep(2)
    return active


def _wait_for_no_active_backups(rds, instance_id: str, timeout_s: float) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    active: list[dict] = _active_backups(rds, instance_id)
    while time.monotonic() < deadline:
        active = _active_backups(rds, instance_id)
        if not active:
            return active
        time.sleep(2)
    return active


def _delete_instance(rds, instance_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=instance_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFoundFault":
            return
        raise
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
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
