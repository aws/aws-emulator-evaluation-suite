"""e2e-plan-selection-backup-job-to-recovery-point."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-plan-selection-backup-job-to-recovery-point"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A plan+selection+on-demand job reaches COMPLETED and its recovery point is listed by
    ListRecoveryPointsByBackupVault; deleting the recovery point, selection and plan removes them."""
    # IAM role propagation + a full DynamoDB backup-job-to-COMPLETED round trip can take
    # several minutes on real AWS, beyond the default per-check budget.
    # Create the IAM role first so its (eventually-consistent) trust/permission propagation
    # has the most possible wall-clock time to settle while the table/vault/plan are created.
    role_arn = _create_backup_service_role(ctx)
    table = _create_table(ctx)
    vault_name = _create_vault(ctx)
    backup = ctx.client("backup")

    plan_id = _create_plan(ctx, vault_name)
    selection_id = _create_selection_with_retry(ctx, plan_id, table["arn"], role_arn, timeout_s=90, interval_s=3)

    job = _backup_to_completed(ctx, vault_name, table["arn"], role_arn, timeout_s=1200)
    rp_arn = job["RecoveryPointArn"]
    ctx.on_cleanup(lambda: _delete_recovery_point_quietly(backup, vault_name, rp_arn))

    # The vault listing is eventually consistent with the job's completion, so poll it.
    listed_deadline = time.monotonic() + 120
    while True:
        rps = backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name)["RecoveryPoints"]
        if any(rp["RecoveryPointArn"] == rp_arn for rp in rps) or time.monotonic() >= listed_deadline:
            break
        time.sleep(5)
    assert any(rp["RecoveryPointArn"] == rp_arn for rp in rps), "recovery point not visible in vault listing"

    backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    _poll_recovery_point_gone(ctx, vault_name, rp_arn)

    backup.delete_backup_selection(BackupPlanId=plan_id, SelectionId=selection_id)
    code_sel, message_sel = _error(lambda: backup.get_backup_selection(BackupPlanId=plan_id, SelectionId=selection_id))
    assert code_sel == "ResourceNotFoundException", f"expected selection removed, got {code_sel}"
    expected_message_sel = "Cannot find Backup selection"
    assert message_sel == expected_message_sel, f"expected message {expected_message_sel!r}, got {message_sel!r}"

    backup.delete_backup_plan(BackupPlanId=plan_id)
    code_plan, message_plan = _error(lambda: backup.get_backup_plan(BackupPlanId=plan_id))
    assert code_plan == "ResourceNotFoundException", f"expected plan removed, got {code_plan}"
    expected_message_plan = "Failed reading Backup plan with provided version"
    assert message_plan == expected_message_plan, f"expected message {expected_message_plan!r}, got {message_plan!r}"


# ===== helpers =====

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


def _safe_call(fn):
    """Run a delete; a not-found refusal (DeleteBackupSelection on a deleted plan answers
    InvalidParameterValueException "Cannot find Backup plan") means it is already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "InvalidParameterValueException" and "cannot find backup plan" in err.get("Message", "").lower():
            return
        if err["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(BackupVaultName=name, BackupVaultTags={"sim2real-check": CHECK})
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=name)))
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)))
    return role_arn


def _create_plan(ctx, vault_name):
    backup = ctx.client("backup")
    plan_name = ctx.unique_name("sim2real-backup-plan-")
    resp = backup.create_backup_plan(
        BackupPlan={
            "BackupPlanName": plan_name,
            "Rules": [
                {
                    "RuleName": "daily",
                    "TargetBackupVaultName": vault_name,
                    "ScheduleExpression": "cron(0 5 * * ? *)",
                }
            ],
        },
        BackupPlanTags={"sim2real-check": CHECK},
    )
    plan_id = resp["BackupPlanId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: backup.delete_backup_plan(BackupPlanId=plan_id)))
    return plan_id


def _create_selection(ctx, plan_id, resource_arn, role_arn):
    backup = ctx.client("backup")
    sel_name = ctx.unique_name("sim2real-backup-sel-")
    resp = backup.create_backup_selection(
        BackupPlanId=plan_id,
        BackupSelection={"SelectionName": sel_name, "IamRoleArn": role_arn, "Resources": [resource_arn]},
    )
    selection_id = resp["SelectionId"]
    ctx.on_cleanup(
        lambda: _safe_call(lambda: backup.delete_backup_selection(BackupPlanId=plan_id, SelectionId=selection_id))
    )
    return selection_id


def _create_selection_with_retry(ctx, plan_id, resource_arn, role_arn, timeout_s=120, interval_s=5):
    """A freshly-created IAM role may not yet be assumable by the AWS Backup service
    (IAM trust-policy/permission propagation lag); retry CreateBackupSelection on the
    transient InvalidParameterValueException/'cannot be assumed' response until it clears."""
    ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return _create_selection(ctx, plan_id, resource_arn, role_arn)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "assum" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"backup selection role trust never propagated within {timeout_s}s: {last_err}")


# A job started right after the table turns ACTIVE can fail while AWS Backup is still enabling
# backups for it; that job is retried with a new one.
_ENABLING = "backups are being enabled"


def _backup_to_completed(ctx, vault_name, resource_arn, role_arn, timeout_s=1200):
    """Start an on-demand job and poll it to COMPLETED, starting a new job (every 2 s, to the
    deadline) while one fails because backups are still being enabled for the table."""
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 15.0))
    deadline = time.monotonic() + timeout_s
    while True:
        job_id = _start_backup_job_with_role_retry(ctx, vault_name, resource_arn, role_arn, timeout_s=60, interval_s=3)
        try:
            return _poll_backup_job_to_completed(ctx, job_id, timeout_s=max(1.0, deadline - time.monotonic()), interval_s=5)
        except AssertionError as exc:
            if _ENABLING not in str(exc).lower() or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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


def _start_backup_job_with_role_retry(ctx, vault_name, resource_arn, role_arn, timeout_s=120, interval_s=5):
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry StartBackupJob on the transient
    InvalidParameterValueException/'insufficient permissions' response until it clears."""
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


def _delete_recovery_point_quietly(backup, vault_name, rp_arn, timeout_s=300, interval_s=2):
    """Teardown: delete the recovery point if the run did not, and wait until it is gone so the
    vault delete that runs next does not meet a vault that still holds it."""
    try:
        backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"recovery point {rp_arn} still present {timeout_s} s after DeleteRecoveryPoint")


def _poll_recovery_point_gone(ctx, vault_name, rp_arn, timeout_s=90, interval_s=5):
    backup = ctx.client("backup")
    code, message = _error(
        lambda: backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn),
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    assert code == "ResourceNotFoundException", f"recovery point {rp_arn}: expected ResourceNotFoundException, got {code}"
    assert message == "Cannot find recovery point", f"recovery point {rp_arn}: unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
