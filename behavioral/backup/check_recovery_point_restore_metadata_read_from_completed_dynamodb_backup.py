"""recovery-point-restore-metadata-read-from-completed-dynamodb-backup."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recovery-point-restore-metadata-read-from-completed-dynamodb-backup"
GROUP = "state-machine"
SERVICES = ["backup"]

_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"}
_ROLE_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
)
#: The RestoreMetadata keys GetRecoveryPointRestoreMetadata returns for a DynamoDB recovery point.
_RESTORE_METADATA_KEYS = frozenset(
    {
        "autoScaling",
        "aws:backup:request-id",
        "encryptionType",
        "kmsMasterKeyArn",
        "originalTableName",
        "primaryPartitionKey",
        "provisionedReadCapacityUnits",
        "provisionedWriteCapacityUnits",
        "secondaryIndices",
        "sortKey",
        "stream",
        "targetTableName",
    }
)
_TERMINAL_BACKUP = ("COMPLETED", "ABORTED", "FAILED", "EXPIRED", "PARTIAL")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The poll then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, what, fn, pred, *, cap_s, interval_s=5):
    """Poll fn() until pred(value); a deadline the run budget ended raises TimeoutError."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not reached within {cap_s}s; last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _gone(fn, codes):
    """Run a delete, treating the listed not-found codes as already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _delete_table(ddb, name):
    _gone(lambda: ddb.delete_table(TableName=name), ("ResourceNotFoundException",))


def _delete_role(iam, name):
    for arn in _ROLE_POLICIES:
        _gone(
            lambda arn=arn: iam.detach_role_policy(RoleName=name, PolicyArn=arn), ("NoSuchEntity",)
        )
    _gone(lambda: iam.delete_role(RoleName=name), ("NoSuchEntity",))


def _delete_recovery_point(backup, vault, holder):
    """Delete every recovery point the check's backup jobs made and wait until each is gone."""
    for arn in holder.get("all", []):
        _gone(
            lambda arn=arn: backup.delete_recovery_point(
                BackupVaultName=vault, RecoveryPointArn=arn
            ),
            ("ResourceNotFoundException",),
        )
        deadline = time.monotonic() + 300
        while True:
            try:
                backup.describe_recovery_point(BackupVaultName=vault, RecoveryPointArn=arn)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    break
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"recovery point {arn} still present 300 s after DeleteRecoveryPoint"
                )
            time.sleep(3)


def _start_backup_job_with_role_retry(
    ctx, vault_name, resource_arn, role_arn, timeout_s=120, interval_s=5
):
    """Start a backup job, retrying while the fresh role is not yet usable by AWS Backup.

    IAM propagation lag shows as a transient InvalidParameterValueException naming insufficient
    permissions; StartBackupJob is retried on it until it clears.
    """
    backup = ctx.client("backup")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = None
    kwargs = {"BackupVaultName": vault_name, "ResourceArn": resource_arn, "IamRoleArn": role_arn}
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(**kwargs)["BackupJobId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "permission" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_err}"
    )


def _completed_backup_job(ctx, backup, vault, resource_arn, role_arn, recovery_point):
    """Run a backup job to a terminal state and record its recovery point for teardown.

    The job is started once more when the first attempt FAILED because the new role was not yet
    usable.
    """
    for attempt in (1, 2):
        job_id = _start_backup_job_with_role_retry(ctx, vault, resource_arn, role_arn)
        job = _poll(
            ctx,
            f"backup job {job_id} terminal",
            lambda job_id=job_id: backup.describe_backup_job(BackupJobId=job_id),
            lambda j: j["State"] in _TERMINAL_BACKUP,
            cap_s=1200,
            interval_s=10,
        )
        if job.get("RecoveryPointArn"):
            recovery_point.setdefault("all", []).append(job["RecoveryPointArn"])
            recovery_point["arn"] = job["RecoveryPointArn"]
        role_lag = job["State"] == "FAILED" and any(
            w in (job.get("StatusMessage") or "").lower() for w in ("permission", "assume")
        )
        if not (attempt == 1 and role_lag):
            break
    assert job["State"] == "COMPLETED", (
        f"backup job {job['BackupJobId']} ended {job['State']!r}: {job.get('StatusMessage')!r}"
    )
    return job


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRecoveryPointRestoreMetadata describes a completed DynamoDB backup's recovery point.

    It returns the vault and recovery point ARNs, ResourceType DynamoDB, and RestoreMetadata with
    the DynamoDB restore keys, whose originalTableName and primaryPartitionKey are the table's.

    Reference: https://docs.aws.amazon.com/aws-backup/latest/devguide/API_GetRecoveryPointRestoreMetadata.html
    """
    backup = ctx.client("backup")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")

    source = ctx.unique_name("sim2real-backup-src-")
    ctx.on_cleanup(lambda: _delete_table(ddb, source))
    ddb.create_table(
        TableName=source,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )
    ddb.get_waiter("table_exists").wait(
        TableName=source, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    table_arn = ddb.describe_table(TableName=source)["Table"]["TableArn"]

    role = ctx.unique_name("sim2real-backup-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "backup.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )["Role"]["Arn"]
    for arn in _ROLE_POLICIES:
        iam.attach_role_policy(RoleName=role, PolicyArn=arn)

    vault = ctx.unique_name("sim2real-backup-vault-")
    ctx.on_cleanup(
        lambda: _gone(
            lambda: backup.delete_backup_vault(BackupVaultName=vault),
            ("ResourceNotFoundException",),
        )
    )
    vault_arn = backup.create_backup_vault(BackupVaultName=vault, BackupVaultTags=_MANAGED)[
        "BackupVaultArn"
    ]
    recovery_point = {}
    ctx.on_cleanup(lambda: _delete_recovery_point(backup, vault, recovery_point))

    _completed_backup_job(ctx, backup, vault, table_arn, role_arn, recovery_point)

    meta = backup.get_recovery_point_restore_metadata(
        BackupVaultName=vault, RecoveryPointArn=recovery_point["arn"]
    )
    got = (meta.get("BackupVaultArn"), meta.get("RecoveryPointArn"), meta.get("ResourceType"))
    want = (vault_arn, recovery_point["arn"], "DynamoDB")
    assert got == want, (
        f"GetRecoveryPointRestoreMetadata (BackupVaultArn, RecoveryPointArn, ResourceType): "
        f"expected {want!r}, got {got!r}"
    )
    restore_metadata = meta.get("RestoreMetadata") or {}
    missing = sorted(_RESTORE_METADATA_KEYS - restore_metadata.keys())
    assert not missing, (
        f"RestoreMetadata of a DynamoDB recovery point lacks keys {missing!r}; "
        f"got {restore_metadata!r}"
    )
    got = (restore_metadata.get("originalTableName"), restore_metadata.get("primaryPartitionKey"))
    assert got == (source, "pk"), (
        f"RestoreMetadata (originalTableName, primaryPartitionKey): expected {(source, 'pk')!r}, "
        f"got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
