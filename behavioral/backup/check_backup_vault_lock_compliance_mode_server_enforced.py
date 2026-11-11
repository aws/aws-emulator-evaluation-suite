"""backup-vault-lock-compliance-mode-server-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-vault-lock-compliance-mode-server-enforced"
GROUP = "server-side"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A compliance-mode vault lock makes DeleteRecoveryPoint on a recovery point younger than the
    retention floor fail with InvalidRequestException and keeps the point; unlocked, it succeeds."""
    backup = ctx.client("backup")
    table = _create_table(ctx)
    role_arn = _create_backup_service_role(ctx)

    locked_vault = _create_vault(ctx)
    backup.put_backup_vault_lock_configuration(
        BackupVaultName=locked_vault, ChangeableForDays=3, MinRetentionDays=1, MaxRetentionDays=36500
    )
    desc = backup.describe_backup_vault(BackupVaultName=locked_vault)
    assert desc.get("Locked") is True, f"expected Locked=True after put_backup_vault_lock_configuration, got {desc.get('Locked')!r}"

    unlocked_vault = _create_vault(ctx)

    locked_job_id = _start_backup_job_with_role_retry(
        ctx, locked_vault, table["arn"], role_arn, lifecycle={"DeleteAfterDays": 7}
    )
    locked_job = _poll_backup_job_to_completed(ctx, locked_job_id)
    locked_rp_arn = locked_job["RecoveryPointArn"]
    ctx.on_cleanup(lambda: _teardown_locked_vault(ctx, locked_vault, locked_rp_arn))

    code, message = _expect_rejection(
        lambda: backup.delete_recovery_point(BackupVaultName=locked_vault, RecoveryPointArn=locked_rp_arn)
    )
    # A compliance-mode vault lock rejects a premature DeleteRecoveryPoint with
    # InvalidRequestException, not InvalidResourceStateException.
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == (
        "RecoveryPoint cannot be deleted or updated (Backup vault configured with Lock)"
    ), f"actual_message={message!r}"

    # effect absent: the recovery point still exists and was not deleted. describe_recovery_point
    # raises ResourceNotFoundException if it were actually gone, so reaching this assert already
    # proves survival; the field check further confirms the read targeted the same recovery point.
    still_there = backup.describe_recovery_point(BackupVaultName=locked_vault, RecoveryPointArn=locked_rp_arn)
    assert still_there["RecoveryPointArn"] == locked_rp_arn, (
        f"expected recovery point {locked_rp_arn} to survive the rejected delete, "
        f"describe returned {still_there.get('RecoveryPointArn')!r}"
    )
    assert still_there["Status"] == "COMPLETED", f"expected surviving recovery point Status=COMPLETED, got {still_there.get('Status')!r}"

    # positive control: the identical backup/delete cycle on an UNLOCKED vault succeeds
    ctrl_job_id = _start_backup_job_with_role_retry(ctx, unlocked_vault, table["arn"], role_arn)
    ctrl_job = _poll_backup_job_to_completed(ctx, ctrl_job_id)
    ctrl_rp_arn = ctrl_job["RecoveryPointArn"]
    backup.delete_recovery_point(BackupVaultName=unlocked_vault, RecoveryPointArn=ctrl_rp_arn)
    _poll_recovery_point_gone(ctx, unlocked_vault, ctrl_rp_arn)


def _expect_rejection(fn):
    """Call fn(); return its error (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _teardown_locked_vault(ctx, vault_name, rp_arn):
    backup = ctx.client("backup")
    _safe_call(lambda: backup.delete_backup_vault_lock_configuration(BackupVaultName=vault_name))
    _safe_call(lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn))
    # DeleteRecoveryPoint is asynchronous; the vault refuses deletion until the point is gone.
    _poll_recovery_point_gone(ctx, vault_name, rp_arn, timeout_s=180)
    backup.delete_backup_vault(BackupVaultName=vault_name)


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(BackupVaultName=name, BackupVaultTags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _safe_call(lambda: backup.delete_backup_vault(BackupVaultName=name)))
    return name


def _create_backup_service_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-backup-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=name)))
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)))
    return role_arn


def _poll_backup_job_to_completed(ctx, job_id, timeout_s=1200, interval_s=5):
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_state = None
    resp = None
    while time.monotonic() < deadline:
        resp = backup.describe_backup_job(BackupJobId=job_id)
        last_state = resp["State"]
        if last_state == "COMPLETED":
            return resp
        if last_state in ("FAILED", "ABORTED", "EXPIRED"):
            raise AssertionError(f"backup job {job_id} entered {last_state}: {resp.get('StatusMessage')}")
        time.sleep(interval_s)
    raise AssertionError(f"backup job {job_id} did not reach COMPLETED within {timeout_s}s (last {last_state})")


def _start_backup_job_with_role_retry(ctx, vault_name, resource_arn, role_arn, timeout_s=120, interval_s=5, lifecycle=None):
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry StartBackupJob on the transient
    InvalidParameterValueException/'insufficient permissions' response until it clears."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = {"BackupVaultName": vault_name, "ResourceArn": resource_arn, "IamRoleArn": role_arn}
    if lifecycle is not None:
        kwargs["Lifecycle"] = lifecycle
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
    raise AssertionError(f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_err}")


def _poll_recovery_point_gone(ctx, vault_name, rp_arn, timeout_s=90, interval_s=5):
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"recovery point {rp_arn} was not removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
