"""e2e-restore-job-validation-flow."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-restore-job-validation-flow"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A completed backup restores to COMPLETED and PutRestoreValidationResult shows in
    DescribeRestoreJob; restore APIs on a nonexistent recovery point or job are refused as not found.
    """
    backup = ctx.client("backup")

    table_arn = _create_dynamodb_table(ctx)
    role_arn = _create_backup_role(ctx)
    vault_name = _create_backup_vault(ctx)

    job = _start_backup_job_with_retry(ctx, vault_name, table_arn, role_arn)
    job_id = job["BackupJobId"]
    initial_state = backup.describe_backup_job(BackupJobId=job_id)["State"]
    assert initial_state in ("CREATED", "PENDING", "RUNNING", "COMPLETED"), (
        f"unexpected initial backup job state: {initial_state}"
    )

    # --- fast, always-run boundaries against fabricated identifiers ---
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_recovery_point_arn = f"arn:aws:backup:{ctx.region}:{account_id}:recovery-point:{uuid.uuid4()}"
    fake_restore_job_id = str(uuid.uuid4())

    start_restore_code, start_restore_message = _error(
        lambda: backup.start_restore_job(
            RecoveryPointArn=fake_recovery_point_arn,
            Metadata={"targetTableName": ctx.unique_name("sim2real-backup-restored-")},
            IamRoleArn=role_arn,
            ResourceType="DynamoDB",
            IdempotencyToken=ctx.unique_name("sim2real-token-"),
        )
    )
    assert start_restore_code == "InvalidParameterValueException", f"unexpected code: {start_restore_code}"
    expected_start_restore_message = "Cannot find recovery point"
    assert start_restore_message == expected_start_restore_message, (
        f"expected message {expected_start_restore_message!r}, got {start_restore_message!r}"
    )

    describe_restore_code, describe_restore_message = _error(lambda: backup.describe_restore_job(RestoreJobId=fake_restore_job_id))
    assert describe_restore_code == "ResourceNotFoundException", f"unexpected code: {describe_restore_code}"
    expected_describe_restore_message = "Cannot find restore job"
    assert describe_restore_message == expected_describe_restore_message, f"expected message {expected_describe_restore_message!r}, got {describe_restore_message!r}"

    put_validation_code, put_validation_message = _error(
        lambda: backup.put_restore_validation_result(
            RestoreJobId=fake_restore_job_id,
            ValidationStatus="SUCCESSFUL",
            ValidationStatusMessage="sim2real-behavioral-check-should-not-apply",
        )
    )
    assert put_validation_code == "ResourceNotFoundException", f"unexpected code: {put_validation_code}"
    expected_put_validation_message = "Cannot find restore job"
    assert put_validation_message == expected_put_validation_message, f"expected message {expected_put_validation_message!r}, got {put_validation_message!r}"

    get_metadata_code, get_metadata_message = _error(lambda: backup.get_restore_job_metadata(RestoreJobId=fake_restore_job_id))
    assert get_metadata_code == "ResourceNotFoundException", f"unexpected code: {get_metadata_code}"
    expected_get_metadata_message = "Cannot find restore job"
    assert get_metadata_message == expected_get_metadata_message, f"expected message {expected_get_metadata_message!r}, got {get_metadata_message!r}"

    _run_deep_restore_validation_flow(ctx, backup, vault_name, role_arn, job_id)


def _run_deep_restore_validation_flow(ctx, backup, vault_name: str, role_arn: str, job_id: str) -> None:
    """Wait for the real backup job to complete, start a real restore job, wait for
    it to complete, submit a self-run validation result, and assert it's observable."""
    state = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id)["State"],
        lambda s: s in ("COMPLETED", "ABORTED", "FAILED", "EXPIRED", "PARTIAL"),
        timeout_s=1200,
        interval_s=15,
    )
    assert state == "COMPLETED", f"backup job did not complete: {state}"
    recovery_point_arn = backup.describe_backup_job(BackupJobId=job_id)["RecoveryPointArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_recovery_point(ctx, vault_name, recovery_point_arn))

    restored_name = ctx.unique_name("sim2real-backup-restored-")
    restore = backup.start_restore_job(
        RecoveryPointArn=recovery_point_arn,
        Metadata={"targetTableName": restored_name},
        IamRoleArn=role_arn,
        ResourceType="DynamoDB",
        IdempotencyToken=ctx.unique_name("sim2real-token-"),
    )
    restore_job_id = restore["RestoreJobId"]

    def _cleanup_restored_table() -> None:
        ddb = ctx.client("dynamodb")
        try:
            ddb.delete_table(TableName=restored_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "TableNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup_restored_table)

    restore_status = _poll_until(
        lambda: backup.describe_restore_job(RestoreJobId=restore_job_id)["Status"],
        lambda s: s in ("COMPLETED", "ABORTED", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert restore_status == "COMPLETED", f"restore job did not complete: {restore_status}"

    # --- submit the self-run validation result ---
    backup.put_restore_validation_result(
        RestoreJobId=restore_job_id,
        ValidationStatus="SUCCESSFUL",
        ValidationStatusMessage="sim2real-behavioral-check-validated",
    )

    validation_status = _poll_until(
        lambda: backup.describe_restore_job(RestoreJobId=restore_job_id)["ValidationStatus"],
        lambda s: s == "SUCCESSFUL",
        timeout_s=60,
        interval_s=3,
    )
    assert validation_status == "SUCCESSFUL", f"unexpected ValidationStatus: {validation_status}"
    described = backup.describe_restore_job(RestoreJobId=restore_job_id)
    assert described["ValidationStatusMessage"] == "sim2real-behavioral-check-validated", (
        f"unexpected ValidationStatusMessage: {described.get('ValidationStatusMessage')!r}"
    )

    # --- the dedicated metadata API answers for the restore job, but masks the
    # sensitive DynamoDB TargetTableName it was given (the value comes back as the
    # literal sentinel below, never the table name we
    # submitted) -- overly-permissive detection: a target that echoes the real name
    # back here is leaking metadata AWS Backup does not expose through this call ---
    metadata = backup.get_restore_job_metadata(RestoreJobId=restore_job_id)["Metadata"]
    lowered = {k.lower(): v for k, v in metadata.items()}
    assert lowered.get("targettablename") == "VALUE_NOT_DISPLAYED", (
        f"expected AWS Backup to mask targetTableName in restore job metadata, got: {lowered.get('targettablename')!r}"
    )

    # --- terminal read at the consumer: the restore's actual effect is a live DynamoDB
    # table, not merely AWS Backup's own bookkeeping about it ---
    ddb = ctx.client("dynamodb")
    restored_table = ddb.describe_table(TableName=restored_name)["Table"]
    assert restored_table["TableStatus"] == "ACTIVE", (
        f"restored table {restored_name} not ACTIVE at the DynamoDB consumer: {restored_table['TableStatus']}"
    )
    restored_keys = {k["AttributeName"] for k in restored_table["KeySchema"]}
    assert restored_keys == {"pk"}, f"restored table has unexpected key schema: {restored_keys}"


# ===== helpers =====

def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except Exception:
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _error(fn, *, timeout_s: float = 0.0, interval_s: float = 3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS once timeout_s has passed raises, so an accepted call is reported as such and not
    as a code mismatch."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _create_dynamodb_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-src-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-backup"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=30,
        interval_s=2,
    )
    return ddb.describe_table(TableName=name)["Table"]["TableArn"]


def _create_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-backup"}],
    )
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup_role() -> None:
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_backup_vault(ctx) -> str:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(
        BackupVaultName=name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=name))
    return name


def _start_backup_job_with_retry(ctx, vault_name: str, resource_arn: str, role_arn: str) -> dict:
    backup = ctx.client("backup")
    deadline = time.monotonic() + 120
    last_err = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name,
                ResourceArn=resource_arn,
                IamRoleArn=role_arn,
                IdempotencyToken=ctx.unique_name("sim2real-token-"),
            )
        except Exception as err:  # IAM role propagation lag
            last_err = err
            time.sleep(5)
    raise AssertionError(f"StartBackupJob never succeeded (IAM propagation?): {last_err}")


def _best_effort_delete_recovery_point(ctx, vault_name: str, recovery_point_arn: str) -> None:
    """Delete the recovery point and wait until it is gone: the delete settles asynchronously,
    and the vault delete that runs next refuses a vault that still holds the point."""
    from botocore.exceptions import ClientError

    backup = ctx.client("backup")
    try:
        backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"recovery point {recovery_point_arn} still present 300 s after DeleteRecoveryPoint")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

