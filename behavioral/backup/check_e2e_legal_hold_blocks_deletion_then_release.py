"""e2e-legal-hold-blocks-deletion-then-release."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-legal-hold-blocks-deletion-then-release"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Legal hold blocks DeleteRecoveryPoint while active; CancelLegalHold lifts the block.
    A backup job's not-yet-created recovery point is neither deletable nor describable.
    """
    backup = ctx.client("backup")

    table_arn = _create_dynamodb_table(ctx)
    role_arn = _create_backup_role(ctx, restores=False)
    vault_name = _create_backup_vault(ctx)

    job = _start_backup_job_with_retry(ctx, vault_name, table_arn, role_arn)
    job_id = job["BackupJobId"]
    initial_state = backup.describe_backup_job(BackupJobId=job_id)["State"]
    assert initial_state in ("CREATED", "PENDING", "RUNNING", "COMPLETED"), (
        f"unexpected initial backup job state: {initial_state}"
    )

    # --- boundary: the job's recovery point does not exist yet ---
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_recovery_point_arn = (
        f"arn:aws:backup:{ctx.region}:{account_id}:recovery-point:"
        f"{ctx.unique_name('sim2real-nonexistent-')}"
    )
    describe_code, describe_message = _error(
        lambda: backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=fake_recovery_point_arn)
    )
    assert describe_code == "ResourceNotFoundException", f"unexpected code: {describe_code}"
    expected_describe_message = "Cannot find recovery point"
    assert describe_message == expected_describe_message, f"expected message {expected_describe_message!r}, got {describe_message!r}"
    delete_code, delete_message = _error(
        lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=fake_recovery_point_arn)
    )
    assert delete_code == "ResourceNotFoundException", f"unexpected code: {delete_code}"
    expected_delete_message = "Cannot find recovery point"
    assert delete_message == expected_delete_message, f"expected message {expected_delete_message!r}, got {delete_message!r}"

    # The deep flow creates and releases the hold itself, so there is no separate
    # shallow-release path to fall back to any more.
    _run_deep_protective_flow(ctx, backup, vault_name, table_arn, job_id)


def _run_deep_protective_flow(ctx, backup, vault_name: str, table_arn: str, job_id: str) -> None:
    """Wait for the real backup job to complete, then create a legal hold over the
    real recovery point and assert its actual protective consequence, and its
    release."""
    state = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id)["State"],
        lambda s: s in ("COMPLETED", "ABORTED", "FAILED", "EXPIRED", "PARTIAL"),
        timeout_s=1200,
        interval_s=15,
    )
    assert state == "COMPLETED", f"backup job did not complete: {state}"
    recovery_point_arn = backup.describe_backup_job(BackupJobId=job_id)["RecoveryPointArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_recovery_point(ctx, vault_name, recovery_point_arn, None))

    # The recovery point already exists, so ToDate=now is valid and necessarily
    # covers its creation timestamp.
    now = datetime.now(timezone.utc)
    hold = backup.create_legal_hold(
        Title=ctx.unique_name("sim2real-backup-hold-"),
        Description="sim2real behavioral check legal hold",
        RecoveryPointSelection={
            "ResourceIdentifiers": [table_arn],
            "DateRange": {"FromDate": now - timedelta(days=365), "ToDate": now},
        },
    )
    legal_hold_id = hold["LegalHoldId"]
    ctx.on_cleanup(lambda: _best_effort_cancel_legal_hold(ctx, legal_hold_id))
    ctx.on_cleanup(lambda: _best_effort_delete_recovery_point(ctx, vault_name, recovery_point_arn, legal_hold_id))

    hold_status = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=legal_hold_id)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    assert hold_status == "ACTIVE", f"legal hold never became ACTIVE: {hold_status}"

    def _hold_covers_point() -> bool:
        points = backup.list_recovery_points_by_legal_hold(LegalHoldId=legal_hold_id).get("RecoveryPoints", [])
        return any(p.get("RecoveryPointArn") == recovery_point_arn for p in points)

    covered = _poll_until(_hold_covers_point, lambda ok: ok, timeout_s=300, interval_s=10)
    assert covered, "legal hold never attached to the target recovery point"

    # --- negative: deletion is blocked while the hold is active ---
    # DisassociateRecoveryPoint
    # blocked under a legal hold raises InvalidResourceStateException, but
    # DeleteRecoveryPoint under the same hold raises InvalidRequestException instead --
    # different operations, different codes, for the identical protective state.
    code, message = _error(
        lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn)
    )
    assert code == "InvalidRequestException", f"unexpected code while held: {code}"
    expected_message = "The recovery point cannot be deleted because it has active legal hold(s)."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the recovery point is still there, not deleted/deleting
    still_there = backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn)
    assert still_there["RecoveryPointArn"] == recovery_point_arn
    assert still_there["Status"] != "DELETING"

    # --- release the hold ---
    backup.cancel_legal_hold(LegalHoldId=legal_hold_id, CancelDescription="sim2real behavioral check release")
    cancel_status = _poll_until(
        lambda: backup.get_legal_hold(LegalHoldId=legal_hold_id)["Status"],
        lambda s: s == "CANCELED",
        timeout_s=300,
        interval_s=10,
    )
    assert cancel_status == "CANCELED", f"legal hold never became CANCELED: {cancel_status}"

    # --- positive control: the identical delete call now succeeds ---
    backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn)

    gone_code, _gone_message = _error(
        lambda: backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=recovery_point_arn),
        timeout_s=60,
        interval_s=5,
    )
    assert gone_code == "ResourceNotFoundException", (
        f"recovery point was never actually removed after the hold was released: {gone_code}"
    )
    assert _gone_message == "Cannot find recovery point", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_gone_message!r}"
    )



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
    return last


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
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    table_status = _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert table_status == "ACTIVE", f"dynamodb table never became ACTIVE: {table_status}"
    return ddb.describe_table(TableName=name)["Table"]["TableArn"]


def _create_backup_role(ctx, *, restores: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    import json

    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy_arns = ["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"]
    if restores:
        policy_arns.append("arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores")
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
    vault_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"}
    backup.create_backup_vault(BackupVaultName=name, BackupVaultTags=vault_tags)
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


def _best_effort_delete_recovery_point(ctx, vault_name: str, recovery_point_arn: str, legal_hold_id: str | None) -> None:
    # A legal hold blocks DeleteRecoveryPoint (that is this check's own subject), and
    # ctx.on_cleanup runs LIFO, so this fires before the hold-cancel cleanup registered
    # earlier in the run. Release the hold here too, or an early failure leaks the vault.
    # Both the cancel and the delete settle asynchronously, and the vault delete that runs
    # after this refuses a vault that still holds the point, so wait for each to finish.
    from botocore.exceptions import ClientError

    backup = ctx.client("backup")
    if legal_hold_id is not None:
        _best_effort_cancel_legal_hold(ctx, legal_hold_id)
        try:
            _poll_until(
                lambda: backup.get_legal_hold(LegalHoldId=legal_hold_id)["Status"],
                lambda s: s == "CANCELED",
                timeout_s=300,
                interval_s=10,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
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


def _best_effort_cancel_legal_hold(ctx, legal_hold_id: str) -> None:
    backup = ctx.client("backup")
    try:
        status = backup.get_legal_hold(LegalHoldId=legal_hold_id)["Status"]
        if status in ("ACTIVE", "CREATING"):
            backup.cancel_legal_hold(LegalHoldId=legal_hold_id, CancelDescription="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
