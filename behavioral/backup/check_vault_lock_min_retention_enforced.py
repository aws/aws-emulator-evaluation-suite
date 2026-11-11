"""vault-lock-min-retention-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vault-lock-min-retention-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In a vault locked with a minimum retention, DeleteRecoveryPoint on a younger recovery point
    is rejected with InvalidRequestException and the point remains, while the same delete in an
    unlocked vault succeeds."""
    backup = ctx.client("backup")
    role_arn = _create_backup_iam_role(
        ctx, ["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"]
    )
    resource_arn = _create_table(ctx)

    locked_vault = ctx.unique_name("sim2real-lockedvault-")
    backup.create_backup_vault(
        BackupVaultName=locked_vault,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-lockedvault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=locked_vault))

    unlocked_vault = ctx.unique_name("sim2real-unlockedvault-")
    backup.create_backup_vault(
        BackupVaultName=unlocked_vault,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-unlockedvault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=unlocked_vault))

    # Lock the vault with a 1-day minimum retention, in "changeable" grace mode so the check can
    # clean up after itself.
    backup.put_backup_vault_lock_configuration(
        BackupVaultName=locked_vault, MinRetentionDays=1, MaxRetentionDays=36500, ChangeableForDays=3
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault_lock_configuration(BackupVaultName=locked_vault))
    locked_desc = backup.describe_backup_vault(BackupVaultName=locked_vault)
    assert locked_desc.get("Locked") is True, f"expected the vault lock to be active, got {locked_desc}"

    # A locked vault refuses a recovery point whose lifecycle falls outside [Min, Max] retention,
    # and an unset lifecycle means "keep forever", which exceeds MaxRetentionDays.
    locked_job = _start_backup_job_with_retry(
        backup,
        BackupVaultName=locked_vault,
        ResourceArn=resource_arn,
        IamRoleArn=role_arn,
        Lifecycle={"DeleteAfterDays": 7},
    )
    locked_completed = _wait_for_backup_job_state(backup, locked_job["BackupJobId"], {"COMPLETED", "FAILED"})
    assert locked_completed["State"] == "COMPLETED", f"locked-vault backup job failed: {locked_completed}"
    locked_rp_arn = locked_completed["RecoveryPointArn"]

    def _cleanup_locked_rp():
        # The lock blocks this delete, so lift it first (the vault is still in its changeable window).
        backup.delete_backup_vault_lock_configuration(BackupVaultName=locked_vault)
        backup.delete_recovery_point(BackupVaultName=locked_vault, RecoveryPointArn=locked_rp_arn)
        _poll_recovery_point_gone(backup, locked_vault, locked_rp_arn)

    ctx.on_cleanup(_cleanup_locked_rp)

    unlocked_job = _start_backup_job_with_retry(
        backup, BackupVaultName=unlocked_vault, ResourceArn=resource_arn, IamRoleArn=role_arn
    )
    unlocked_completed = _wait_for_backup_job_state(backup, unlocked_job["BackupJobId"], {"COMPLETED", "FAILED"})
    assert unlocked_completed["State"] == "COMPLETED", f"unlocked-vault backup job failed: {unlocked_completed}"
    unlocked_rp_arn = unlocked_completed["RecoveryPointArn"]

    def _cleanup_unlocked_rp():
        from botocore.exceptions import ClientError

        try:
            backup.delete_recovery_point(BackupVaultName=unlocked_vault, RecoveryPointArn=unlocked_rp_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _poll_recovery_point_gone(backup, unlocked_vault, unlocked_rp_arn)

    ctx.on_cleanup(_cleanup_unlocked_rp)

    code, message = _error(
        lambda: backup.delete_recovery_point(BackupVaultName=locked_vault, RecoveryPointArn=locked_rp_arn)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = "RecoveryPoint cannot be deleted or updated (Backup vault configured with Lock)"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the recovery point is still there, untouched.
    still_there = backup.describe_recovery_point(BackupVaultName=locked_vault, RecoveryPointArn=locked_rp_arn)
    assert still_there["RecoveryPointArn"] == locked_rp_arn, (
        f"locked recovery point {locked_rp_arn} disappeared despite the rejected delete: {still_there}"
    )

    # Positive control: the same kind of recovery point, minus the lock, deletes cleanly -- and the
    # terminal read is an independent one, at the destination, confirming it is actually gone.
    backup.delete_recovery_point(BackupVaultName=unlocked_vault, RecoveryPointArn=unlocked_rp_arn)
    _poll_recovery_point_gone(backup, unlocked_vault, unlocked_rp_arn)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available and must not
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned: {result!r}")


def _create_backup_iam_role(ctx, managed_policy_arns):
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for policy_arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return ddb.describe_table(TableName=name)["Table"]["TableArn"]


def _start_backup_job_with_retry(backup, retries=9, delay=10.0, **kwargs):
    """Bounded retry (deadline = retries * delay) absorbing IAM role propagation lag: the role was
    just created and its managed-policy attachments may not yet be visible to the backup service."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(retries):
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay)
    raise last_exc


def _poll_recovery_point_gone(backup, vault_name, rp_arn, timeout_s=90.0, interval_s=5.0):
    """Not a use of `_error`: a describe that still SUCCEEDS here means "not yet deleted,
    keep polling", the opposite of `_error`'s "unexpected success" meaning for a rejection."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"recovery point {rp_arn} was not removed within {timeout_s}s")


def _wait_for_backup_job_state(backup, job_id, terminal_states, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = backup.describe_backup_job(BackupJobId=job_id)
        if last["State"] in terminal_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"backup job {job_id} did not reach {terminal_states} within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
