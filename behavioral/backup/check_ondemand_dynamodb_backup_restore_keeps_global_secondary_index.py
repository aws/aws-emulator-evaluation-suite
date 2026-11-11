"""ondemand-dynamodb-backup-restore-keeps-global-secondary-index."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ondemand-dynamodb-backup-restore-keeps-global-secondary-index"
GROUP = "state-machine"
SERVICES = ["backup"]

_INDEX = "by-owner"
_ITEM = {"pk": {"S": "order-1"}, "owner": {"S": "alice"}, "total": {"N": "42"}}
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"}
_ROLE_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
)
_TERMINAL_BACKUP = ("COMPLETED", "ABORTED", "FAILED", "EXPIRED", "PARTIAL")
_TERMINAL_RESTORE = ("COMPLETED", "ABORTED", "FAILED")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
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


def _delete_restored_table(backup, ddb, restore_job, name, *, wait_s=900):
    """Wait for a started restore job to end, so the table it creates exists to delete, then
    delete that table."""
    job_id = restore_job.get("id")
    if job_id is not None:
        deadline = time.monotonic() + wait_s
        while backup.describe_restore_job(RestoreJobId=job_id)["Status"] not in _TERMINAL_RESTORE:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"restore job {job_id} still running {wait_s}s into teardown")
            time.sleep(10)
    _delete_table(ddb, name)


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
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry StartBackupJob on the transient
    InvalidParameterValueException/'insufficient permissions' response until it clears."""
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
    """Run a backup job to a terminal state, starting it once more when the first attempt FAILED
    because the new role was not yet usable; records the recovery point for teardown."""
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


def _gsi_summary(table):
    """(IndexName, KeySchema, ProjectionType) for each GSI of a DescribeTable payload."""
    return sorted(
        (
            g["IndexName"],
            tuple((k["AttributeName"], k["KeyType"]) for k in g["KeySchema"]),
            g["Projection"]["ProjectionType"],
        )
        for g in table.get("GlobalSecondaryIndexes", [])
    )


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:e2e",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An on-demand AWS Backup of a DynamoDB table with a global secondary index restores to a
    table that has the same index, ACTIVE and answering a query for the backed-up item.

    Reference: https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-dynamodb.html
    """
    backup = ctx.client("backup")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")

    source = ctx.unique_name("sim2real-backup-src-")
    ctx.on_cleanup(lambda: _delete_table(ddb, source))
    ddb.create_table(
        TableName=source,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "owner", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[
            {
                "IndexName": _INDEX,
                "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )
    ddb.get_waiter("table_exists").wait(
        TableName=source, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    ddb.put_item(TableName=source, Item=_ITEM)
    src_table = ddb.describe_table(TableName=source)["Table"]
    expected_gsis = [(_INDEX, (("owner", "HASH"),), "ALL")]
    assert _gsi_summary(src_table) == expected_gsis, (
        f"source table GSIs: expected {expected_gsis!r}, got {_gsi_summary(src_table)!r}"
    )

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
    backup.create_backup_vault(BackupVaultName=vault, BackupVaultTags=_MANAGED)
    recovery_point = {}
    ctx.on_cleanup(lambda: _delete_recovery_point(backup, vault, recovery_point))

    _completed_backup_job(ctx, backup, vault, src_table["TableArn"], role_arn, recovery_point)

    restored = ctx.unique_name("sim2real-backup-restored-")
    restore_job = {}
    ctx.on_cleanup(lambda: _delete_restored_table(backup, ddb, restore_job, restored))
    restore_id = restore_job["id"] = backup.start_restore_job(
        RecoveryPointArn=recovery_point["arn"],
        Metadata={"targetTableName": restored},
        IamRoleArn=role_arn,
        ResourceType="DynamoDB",
        IdempotencyToken=ctx.unique_name("sim2real-token-"),
    )["RestoreJobId"]
    restore = _poll(
        ctx,
        f"restore job {restore_id} terminal",
        lambda: backup.describe_restore_job(RestoreJobId=restore_id),
        lambda r: r["Status"] in _TERMINAL_RESTORE,
        cap_s=1200,
        interval_s=10,
    )
    assert restore["Status"] == "COMPLETED", (
        f"restore job {restore_id} ended {restore['Status']!r}: {restore.get('StatusMessage')!r}"
    )

    table = _poll(
        ctx,
        f"restored table {restored} and its index ACTIVE",
        lambda: ddb.describe_table(TableName=restored)["Table"],
        lambda t: (
            t["TableStatus"] == "ACTIVE"
            and all(g.get("IndexStatus") == "ACTIVE" for g in t.get("GlobalSecondaryIndexes", []))
        ),
        cap_s=600,
    )
    assert _gsi_summary(table) == expected_gsis, (
        f"the restored table must keep the source's GSI {expected_gsis!r}; got "
        f"{_gsi_summary(table)!r}"
    )
    found = ddb.query(
        TableName=restored,
        IndexName=_INDEX,
        KeyConditionExpression="#o = :o",
        ExpressionAttributeNames={"#o": "owner"},
        ExpressionAttributeValues={":o": _ITEM["owner"]},
    )["Items"]
    assert found == [_ITEM], (
        f"a query on the restored GSI {_INDEX!r} must return the backed-up item {_ITEM!r}; "
        f"got {found!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
