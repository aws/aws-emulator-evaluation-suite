"""delete-recovery-point-wrong-state-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-recovery-point-wrong-state-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRecoveryPoint on the recovery point of a still-running EFS backup job fails with
    ResourceNotFoundException; the same call succeeds once the job completes."""
    backup = ctx.client("backup")
    efs = ctx.client("efs")

    role_arn = _create_backup_role(ctx)

    vault_name = ctx.unique_name("sim2real-behav-vault-")
    backup.create_backup_vault(BackupVaultName=vault_name)
    ctx.on_cleanup(lambda: _safe(lambda: backup.delete_backup_vault(BackupVaultName=vault_name)))

    token = ctx.unique_name("sim2real-behav-tok-")
    fs = efs.create_file_system(CreationToken=token, PerformanceMode="generalPurpose")
    fs_id = fs["FileSystemId"]
    ctx.on_cleanup(lambda: _safe(lambda: efs.delete_file_system(FileSystemId=fs_id)))
    efs.tag_resource(
        ResourceId=fs_id,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-efs-")}],
    )
    _wait_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda state: state == "available",
        timeout_s=120,
    )
    fs_arn = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["FileSystemArn"]

    job = _start_backup_job_with_retry(backup, vault_name, fs_arn, role_arn)
    job_id = job["BackupJobId"]
    rp_arn = job.get("RecoveryPointArn")
    assert rp_arn, "StartBackupJob for an EFS resource must return RecoveryPointArn immediately"

    # negative: the job is still running, so the reserved ARN is not yet a real,
    # queryable recovery point
    job_state_before = backup.describe_backup_job(BackupJobId=job_id)["State"]
    assert job_state_before != "COMPLETED", (
        "the job completed before the negative could be observed; the EFS backup was "
        "faster than this check's timing assumption"
    )
    code, message = _error(
        lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException (job_state={job_state_before!r}), got {code}"
    )
    assert message == "Cannot find recovery point", f"actual_message={message!r}"

    # effect absent: the failed delete did not conjure the recovery point into existence
    assert _recovery_point_status(backup, vault_name, rp_arn) is None

    # restore: wait for the backup job to reach a terminal state
    final_state = _wait_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id)["State"],
        lambda state: state in ("COMPLETED", "FAILED", "ABORTED", "EXPIRED", "PARTIAL"),
        timeout_s=180,
        interval_s=2,
    )
    assert final_state == "COMPLETED", f"EFS backup job ended in unexpected state {final_state}"

    # once terminal, the recovery point is indexed and describable
    desc = backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    assert desc["RecoveryPointArn"] == rp_arn
    assert desc["Status"] == "COMPLETED", f"unexpected recovery point status {desc['Status']!r}"

    # positive control: the identical delete call now succeeds
    backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)

    # deletes prove gone and unusable: an independent read now 404s, and so does a
    # second delete on the same, now-dead, id
    final_status = _wait_until(
        lambda: _recovery_point_status(backup, vault_name, rp_arn),
        lambda status: status is None,
        timeout_s=60,
    )
    assert final_status is None
    second_delete_code, second_delete_message = _error(
        lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"deleting an already-deleted recovery point must still 404, got {second_delete_code}"
    )
    assert second_delete_message == "Cannot find recovery point", f"actual_message={second_delete_message!r}"


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "FileSystemNotFound",
            "NoSuchEntity",
            "ResourceNotFoundException",
        ):
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _recovery_point_status(backup, vault_name: str, rp_arn: str) -> str | None:
    from botocore.exceptions import ClientError

    try:
        return backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)["Status"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _create_backup_role(ctx) -> str:
    import json

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
