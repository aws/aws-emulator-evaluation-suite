"""start-backup-job-nonexistent-resource-job-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-backup-job-nonexistent-resource-job-fails"
GROUP = "resource-not-found"
SERVICES = ["backup"]

ERR_RESOURCE_NOT_FOUND = "ResourceNotFoundException"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartBackupJob accepts a well-formed ARN of a DynamoDB table that was never created, then
    the job it started transitions to FAILED with an exact not-found message and mints no
    recovery point; the identical call against a real table completes.
    """
    backup = ctx.client("backup")

    vault_name = ctx.unique_name("sim2real-behav-backup-vault-")
    backup.create_backup_vault(BackupVaultName=vault_name, BackupVaultTags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: backup.delete_backup_vault(BackupVaultName=vault_name), ERR_RESOURCE_NOT_FOUND))

    role_arn = _create_backup_service_role(ctx)
    table = _create_table(ctx)

    missing_table_name = ctx.unique_name("sim2real-behav-backup-missing-tbl-")
    missing_arn = f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:table/{missing_table_name}"

    job = _run_until_settled(
        lambda: _start_backup_job_with_role_retry(ctx, vault_name, missing_arn, role_arn),
        lambda job_id: _wait_backup_job_terminal(backup, job_id),
    )
    assert job["State"] == "FAILED", (
        f"expected the job against a nonexistent resource to end FAILED, got {job['State']!r}"
    )
    expected_message = f"Requested resource not found: ResourceArn: {missing_arn} not found"
    assert job["StatusMessage"] == expected_message, (
        f"expected StatusMessage {expected_message!r}, got {job.get('StatusMessage')!r}"
    )
    assert job["MessageCategory"] == "RESOURCE_NOT_FOUND", (
        f"expected MessageCategory 'RESOURCE_NOT_FOUND', got {job.get('MessageCategory')!r}"
    )

    code, message = _error(
        lambda: backup.describe_recovery_point(
            BackupVaultName=vault_name, RecoveryPointArn=job["RecoveryPointArn"]
        )
    )
    assert code == ERR_RESOURCE_NOT_FOUND, (
        f"a FAILED job against a nonexistent resource should mint no recovery point, got {code!r}"
    )
    expected_rp_message = "Cannot find recovery point"
    assert message == expected_rp_message, f"expected message {expected_rp_message!r}, got {message!r}"

    # Positive control: the identical vault/role, against a table that really exists, completes.
    def start_real() -> str:
        job_id = _start_backup_job_with_role_retry(ctx, vault_name, table["arn"], role_arn)
        ctx.on_cleanup(lambda: _delete_job_recovery_point(backup, vault_name, job_id))
        return job_id

    real_job = _run_until_settled(
        start_real,
        lambda job_id: _wait_backup_job_terminal(backup, job_id, timeout_s=1200.0),
        timeout_s=300.0,
    )
    assert real_job["State"] == "COMPLETED", (
        f"backup job against a real table ended {real_job['State']!r}: {real_job.get('StatusMessage')}"
    )
    rp_arn = real_job["RecoveryPointArn"]
    _delete_recovery_point_and_wait(backup, vault_name, rp_arn)
    got = _error(lambda: backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn))
    assert got == (ERR_RESOURCE_NOT_FOUND, expected_rp_message), (
        f"DescribeRecoveryPoint after the recovery point's delete: {got!r}"
    )


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_TRANSIENT_FAILURE_MARKERS = (
    "cannot be assumed by AWS Backup",  # freshly created role's trust policy not yet propagated
    "Please retry later",  # a table's first-ever backup job while its backup infra is enabling
)


def _run_until_settled(start_fn, wait_fn, *, timeout_s: float = 90.0, interval_s: float = 2.0):
    """Start and await a job, retrying the whole attempt while it fails for a transient,
    AWS-declared onboarding reason that exposes no condition to poll; any other terminal state or
    failure is returned as-is.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        job = wait_fn(start_fn())
        message = job.get("StatusMessage", "")
        if job["State"] == "FAILED" and any(marker in message for marker in _TRANSIENT_FAILURE_MARKERS):
            if time.monotonic() >= deadline:
                raise AssertionError(f"job never settled within {timeout_s}s: {message!r}")
            time.sleep(interval_s)
            continue
        return job


def _wait_backup_job_terminal(backup, job_id: str, timeout_s: float = 120.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = backup.describe_backup_job(BackupJobId=job_id)
        if last["State"] in ("COMPLETED", "FAILED", "ABORTED", "EXPIRED", "PARTIAL"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"backup job {job_id} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _create_backup_service_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-backup-svcrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn), "NoSuchEntity"))
    return role_arn


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-backup-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def _start_backup_job_with_role_retry(ctx, vault_name, resource_arn, role_arn, timeout_s=120.0, interval_s=2.0):
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry only on that specific transient rejection.
    """
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "permission" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_err}")


def _delete_job_recovery_point(backup, vault_name: str, job_id: str) -> None:
    """Delete the recovery point a backup job minted, if it minted one."""
    rp_arn = backup.describe_backup_job(BackupJobId=job_id).get("RecoveryPointArn")
    if rp_arn:
        _delete_recovery_point_and_wait(backup, vault_name, rp_arn, timeout_s=50.0)


def _delete_recovery_point_and_wait(
    backup, vault_name: str, rp_arn: str, timeout_s: float = 300.0, interval_s: float = 2.0
) -> None:
    """Delete the recovery point and wait until it is gone, so the vault delete that runs next
    does not meet a vault that still holds it.
    """
    try:
        backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != ERR_RESOURCE_NOT_FOUND:
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == ERR_RESOURCE_NOT_FOUND:
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"recovery point {rp_arn} still present {timeout_s}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
