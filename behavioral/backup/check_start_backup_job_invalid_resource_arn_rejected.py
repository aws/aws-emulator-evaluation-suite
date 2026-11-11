"""start-backup-job-invalid-resource-arn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-backup-job-invalid-resource-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBackupJob with a malformed ResourceArn is rejected at once with AccessDeniedException
    and creates no job; the same vault and role with a real DynamoDB table ARN produce a backup
    job that completes."""
    backup = ctx.client("backup")

    vault_name = ctx.unique_name("sim2real-arn-vault-")
    backup.create_backup_vault(BackupVaultName=vault_name, BackupVaultTags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    role_arn = _create_backup_role(ctx)
    table_name, table_arn = _create_dynamodb_table(ctx)

    code, message = _error(
        lambda: backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn="not-a-real-arn-at-all",
            IamRoleArn=role_arn,
        )
    )
    assert code == "AccessDeniedException", f"unexpected StartBackupJob error code: {code}"
    expected_message = "Insufficient privileges to perform this action."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = backup.list_backup_jobs(ByBackupVaultName=vault_name).get("BackupJobs", [])
    assert after == [], "a backup job was created for a syntactically invalid ResourceArn"


    # Positive control: a real, valid ResourceArn is accepted (not rejected)
    # and the backup job runs to COMPLETED -- proving the vault/
    # role/ARN combination is sound and the earlier rejection was specific
    # to the malformed ARN, not some other precondition.
    started = _start_backup_job_retrying(
        backup,
        BackupVaultName=vault_name,
        ResourceArn=table_arn,
        IamRoleArn=role_arn,
        timeout_s=90.0,
    )
    job_id = started["BackupJobId"]
    job = _wait_backup_job_completed(backup, job_id, timeout_s=1200.0)
    rp_arn = job["RecoveryPointArn"]
    ctx.on_cleanup(lambda: _delete_recovery_point_and_wait(backup, vault_name, rp_arn))


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_dynamodb_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _start_backup_job_retrying(backup, *, timeout_s: float, **kwargs):
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry only on that specific transient rejection and
    re-raise anything else immediately, so an unrelated failure surfaces at once instead of
    being masked for the full timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "permission" in msg.lower():
                last_exc = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_exc}")


def _delete_recovery_point_and_wait(backup, vault_name: str, rp_arn: str, timeout_s: float = 300.0) -> None:
    """Delete the recovery point and wait until it is gone, so the vault delete that runs next
    does not meet a vault that still holds it."""
    from botocore.exceptions import ClientError

    try:
        backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"recovery point {rp_arn} still present {timeout_s}s after delete")


def _wait_backup_job_completed(backup, job_id: str, timeout_s: float = 600.0):
    resp = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id),
        lambda r: r["State"] in ("COMPLETED", "FAILED", "ABORTED", "EXPIRED", "PARTIAL"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert resp["State"] == "COMPLETED", f"backup job ended in {resp['State']}: {resp.get('StatusMessage')}"
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
