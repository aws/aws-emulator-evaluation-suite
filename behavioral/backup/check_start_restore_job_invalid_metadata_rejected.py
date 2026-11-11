"""start-restore-job-invalid-metadata-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-restore-job-invalid-metadata-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartRestoreJob with Metadata lacking the DynamoDB-required TargetTableName is rejected with
    InvalidParameterValueException and creates no restore job; the same recovery point accepts
    the call once TargetTableName is supplied."""
    # A DynamoDB backup job via AWS Backup can take several minutes to leave RUNNING
    # even for an empty table, well past what fits in a routine automated check budget.
    backup = ctx.client("backup")
    ddb = ctx.client("dynamodb")

    role_arn = _create_backup_role(ctx)

    table_name = ctx.unique_name("sim2real-behav-table-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: ddb.delete_table(TableName=table_name)))
    _wait_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=90,
    )
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    # AWS Backup's DynamoDB support relies on point-in-time recovery being enabled on
    # the source table; without it, backup jobs can stall indefinitely instead of
    # reaching a terminal state.
    _retry_continuous_backups_unavailable(
        lambda: ddb.update_continuous_backups(
            TableName=table_name,
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
        )
    )
    _wait_until(
        lambda: ddb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"],
        lambda status: status == "ENABLED",
        timeout_s=30,
    )
    vault_name = ctx.unique_name("sim2real-behav-vault-")
    vault_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    backup.create_backup_vault(BackupVaultName=vault_name, BackupVaultTags=vault_tags)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    final = _start_backup_job_until_completed(backup, vault_name, table_arn, role_arn)
    rp_arn = final["RecoveryPointArn"]
    ctx.on_cleanup(lambda: _delete_recovery_point_and_wait(backup, vault_name, rp_arn))

    # negative: malformed metadata (missing TargetTableName) for a DynamoDB recovery point.
    # IamRoleArn is supplied here too -- this table has continuous backups (PITR) enabled,
    # and real AWS separately requires an IAM role for that "Advanced DynamoDB" restore
    # path, so omitting it would confound the metadata-validation signal under test.
    code, message = _error(
        lambda: backup.start_restore_job(
            RecoveryPointArn=rp_arn, Metadata={"NotARealKey": "x"}, IamRoleArn=role_arn
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected_message = (
        "Invalid restore metadata. Target table name must be provided with restore metadata. "
        f"Restore metadata validation failed for DynamoDB with recoveryPoint {rp_arn}."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no restore job names this check's own recovery point. The listing is
    # account-wide, so only jobs of that recovery point are graded.
    own_jobs = _restore_job_ids_for(backup, rp_arn)
    assert not own_jobs, f"a restore job was created despite the rejected StartRestoreJob call: {own_jobs}"

    # positive control: supplying the required TargetTableName (and the IamRoleArn that
    # AWS requires for a PITR-enabled/"Advanced DynamoDB" restore) is accepted and the
    # restore job runs to COMPLETED, producing the target table.
    restored_name = ctx.unique_name("sim2real-behav-restored-")
    restore = backup.start_restore_job(
        RecoveryPointArn=rp_arn, Metadata={"TargetTableName": restored_name}, IamRoleArn=role_arn
    )
    restore_job_id = restore["RestoreJobId"]
    ctx.on_cleanup(lambda: _delete_restored_table(backup, ddb, restore_job_id, restored_name))
    status = _wait_restore_job_terminal(backup, restore_job_id)
    assert status == "COMPLETED", f"expected the corrected StartRestoreJob call to complete, got status {status!r}"
    listed = _restore_job_ids_for(backup, rp_arn)
    assert listed == {restore_job_id}, f"expected ListRestoreJobs to list only {restore_job_id} for the recovery point, got {listed}"
    restored = ddb.describe_table(TableName=restored_name)["Table"]
    assert restored["TableName"] == restored_name, f"restored table name {restored['TableName']!r}"


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error(fn, *, timeout_s: float = 0.0, interval_s: float = 3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS once timeout_s has passed raises, because a target accepting a call real AWS refuses
    must not read as a code mismatch."""
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


def _wait_restore_job_terminal(backup, restore_job_id: str, timeout_s: float = 480.0) -> str:
    """Poll DescribeRestoreJob until the job leaves PENDING/RUNNING; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = backup.describe_restore_job(RestoreJobId=restore_job_id)["Status"]
        if status in ("COMPLETED", "ABORTED", "FAILED"):
            return status
        time.sleep(2)
    raise AssertionError(f"restore job {restore_job_id} still {status!r} after {timeout_s}s")


def _delete_restored_table(backup, ddb, restore_job_id: str, table_name: str) -> None:
    """The restore job creates the table only when it finishes, so wait for the job before
    deleting the table; a table deleted too early would be re-created by the running job."""
    from botocore.exceptions import ClientError

    _wait_restore_job_terminal(backup, restore_job_id)
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_recovery_point_and_wait(backup, vault_name: str, rp_arn: str, timeout_s: float = 300.0) -> None:
    """Delete the recovery point and wait until it is gone, so the vault delete that runs next
    does not meet a vault that still holds it."""
    from botocore.exceptions import ClientError

    try:
        backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"recovery point {rp_arn} still present {timeout_s}s after delete")


def _wait_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _retry_continuous_backups_unavailable(fn: Callable[[], Any], timeout_s: float = 30.0) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            last_err = err
            time.sleep(3)
    raise AssertionError(f"continuous backups never became available: {last_err}")


def _create_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "backup.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    restore_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=restore_policy_arn)

    def _cleanup():
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=restore_policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _start_backup_job_with_retry(backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )
        except ClientError as err:
            last_err = err
            time.sleep(5)
    raise AssertionError(f"StartBackupJob never succeeded (likely IAM role propagation): {last_err}")


def _start_backup_job_until_completed(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 1200, retry_deadline_s: float = 240
) -> dict:
    """Start a backup job and wait for it to reach COMPLETED. A freshly-created IAM role can
    pass StartBackupJob's own validation and still fail once the backup service actually
    executes the job, while its trust policy or attached policies propagate (AWS reports
    State=FAILED with "The security token included in the request is invalid." or
    "... is not authorized to perform: dynamodb:StartAwsBackupJob ..."). On those transient
    signatures, start a fresh job and retry, bounded by retry_deadline_s."""
    deadline = time.monotonic() + retry_deadline_s
    while True:
        job = _start_backup_job_with_retry(backup, vault_name, resource_arn, role_arn)
        job_id = job["BackupJobId"]
        final = _wait_until(
            lambda: backup.describe_backup_job(BackupJobId=job_id),
            lambda j: j["State"] in ("COMPLETED", "FAILED", "ABORTED", "EXPIRED", "PARTIAL"),
            timeout_s=timeout_s,
            interval_s=5,
        )
        if final["State"] == "COMPLETED":
            return final
        message = (final.get("StatusMessage") or "")
        if (
            final["State"] == "FAILED"
            and ("security token" in message.lower() or "is not authorized to perform" in message)
            and time.monotonic() < deadline
        ):
            time.sleep(5)
            continue
        break
    assert final["State"] == "COMPLETED", (
        f"backup job ended in unexpected state {final['State']} "
        f"(message: {final.get('StatusMessage')})"
    )
    return final


def _restore_job_ids_for(backup, rp_arn: str) -> set:
    """The ids of every listed restore job of recovery point ``rp_arn``, across all pages."""
    ids, token = set(), None
    while True:
        page = backup.list_restore_jobs(**({"NextToken": token} if token else {}))
        ids.update(j["RestoreJobId"] for j in page.get("RestoreJobs", []) if j.get("RecoveryPointArn") == rp_arn)
        token = page.get("NextToken")
        if not token:
            return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
