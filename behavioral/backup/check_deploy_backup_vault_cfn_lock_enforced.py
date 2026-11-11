"""deploy-backup-vault-cfn-lock-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-backup-vault-cfn-lock-enforced"
GROUP = "server-side"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A vault lock applied through CloudFormation makes DeleteRecoveryPoint fail on a recovery
    point inside its retention, while the same delete in an unlocked vault succeeds."""
    cfn = ctx.client("cloudformation")
    backup = ctx.client("backup")

    locked_vault_name = ctx.unique_name("sim2real-cfn-lockvault-")
    stack_name = ctx.unique_name("sim2real-cfn-lockstack-")

    template = json.dumps(
        {
            "Parameters": {"VaultName": {"Type": "String"}},
            "Resources": {
                "BackupVault": {
                    "Type": "AWS::Backup::BackupVault",
                    "Properties": {
                        "BackupVaultName": {"Ref": "VaultName"},
                        "BackupVaultTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"},
                        "LockConfiguration": {
                            "MinRetentionDays": 1,
                            "MaxRetentionDays": 36500,
                            "ChangeableForDays": 3,
                        },
                    },
                }
            },
            "Outputs": {"VaultName": {"Value": {"Ref": "BackupVault"}}},
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "VaultName", "ParameterValue": locked_vault_name}],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-backup"}],
    )
    locked = {"job": None, "rp": None}
    ctx.on_cleanup(lambda: _teardown_locked_stack(backup, cfn, stack_name, locked_vault_name, locked))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    described = backup.describe_backup_vault(BackupVaultName=locked_vault_name)
    assert described["Locked"] is True, f"expected the CFN-deployed vault to report Locked=True, got {described.get('Locked')!r}"
    assert described["MinRetentionDays"] == 1, (
        f"expected MinRetentionDays=1 as templated, got {described.get('MinRetentionDays')!r}"
    )

    role_arn = _create_backup_role(ctx)
    _table_name, table_arn = _create_dynamodb_table(ctx)

    # Locked vault: back up the table with a lifecycle that satisfies MinRetentionDays.
    started_locked = _start_backup_job_retrying(
        backup,
        BackupVaultName=locked_vault_name,
        ResourceArn=table_arn,
        IamRoleArn=role_arn,
        Lifecycle={"DeleteAfterDays": 1},
        timeout_s=90.0,
    )
    locked["job"], locked["rp"] = started_locked["BackupJobId"], started_locked.get("RecoveryPointArn")
    locked_job = _wait_backup_job_completed(backup, started_locked["BackupJobId"])
    locked_rp_arn = locked_job["RecoveryPointArn"]
    locked["rp"] = locked_rp_arn

    code, message = _error(
        lambda: backup.delete_recovery_point(BackupVaultName=locked_vault_name, RecoveryPointArn=locked_rp_arn)
    )
    assert code == "InvalidRequestException", (
        f"expected the CFN-templated MinRetentionDays lock to reject the delete with "
        f"InvalidRequestException, got {code!r}"
    )
    assert message == (
        "RecoveryPoint cannot be deleted or updated (Backup vault configured with Lock)"
    ), f"actual_message={message!r}"

    still_there = backup.describe_recovery_point(BackupVaultName=locked_vault_name, RecoveryPointArn=locked_rp_arn)
    assert still_there["RecoveryPointArn"] == locked_rp_arn, (
        f"expected the rejected delete to leave {locked_rp_arn} in place, "
        f"got {still_there.get('RecoveryPointArn')!r}"
    )

    # Positive control: an unlocked vault backing up the same table can be
    # deleted right away.
    plain_vault_name = ctx.unique_name("sim2real-cfn-plainvault-")
    backup.create_backup_vault(
        BackupVaultName=plain_vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=plain_vault_name))

    started_plain = _start_backup_job_retrying(
        backup,
        BackupVaultName=plain_vault_name,
        ResourceArn=table_arn,
        IamRoleArn=role_arn,
        timeout_s=90.0,
    )
    plain_job = _wait_backup_job_completed(backup, started_plain["BackupJobId"])
    plain_rp_arn = plain_job["RecoveryPointArn"]

    backup.delete_recovery_point(BackupVaultName=plain_vault_name, RecoveryPointArn=plain_rp_arn)
    deleted, deleted_message = _poll_until(
        lambda: _describe_rp_error(backup, plain_vault_name, plain_rp_arn),
        lambda err: err[0] == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert deleted == "ResourceNotFoundException", (
        f"expected the unlocked vault's recovery point to become not-found after delete, got {deleted!r}"
    )
    assert deleted_message == "Cannot find recovery point", f"actual_message={deleted_message!r}"


def _teardown_locked_stack(backup, cfn, stack_name, vault_name, locked) -> None:
    """Teardown inside the lock's ChangeableForDays grace window: drop the lock, delete the
    retained recovery point and wait until it is gone, then delete the stack and wait for it, so a
    vault that still holds a recovery point never leaves the stack in DELETE_FAILED."""
    _best_effort(lambda: backup.delete_backup_vault_lock_configuration(BackupVaultName=vault_name))
    if locked["job"]:
        _best_effort(lambda: backup.stop_backup_job(BackupJobId=locked["job"]))
        _poll_until(
            lambda: backup.describe_backup_job(BackupJobId=locked["job"])["State"],
            lambda state: state in ("COMPLETED", "FAILED", "ABORTED", "EXPIRED", "PARTIAL"),
            timeout_s=600.0,
            interval_s=10.0,
        )
    rp_arn = locked["rp"]
    if rp_arn:
        _best_effort(lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn))
        _poll_until(
            lambda: _describe_rp_error(backup, vault_name, rp_arn)[0],
            lambda code_: code_ == "ResourceNotFoundException",
            timeout_s=120.0,
            interval_s=5.0,
        )
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _best_effort(fn) -> None:
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown only
        pass


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _describe_rp_error(backup, vault_name, rp_arn):
    """Poll probe: DescribeRecoveryPoint's refusal as (code, message), or ("<exists>", None) while
    the recovery point is still describable."""
    from botocore.exceptions import ClientError

    try:
        backup.describe_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return "<exists>", None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-backup"}],
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-backup"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _start_backup_job_retrying(backup, *, timeout_s: float, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError as e:
            last_exc = e
            time.sleep(5)
    raise AssertionError(f"StartBackupJob never succeeded within {timeout_s}s: {last_exc}")


def _wait_backup_job_completed(backup, job_id: str, timeout_s: float = 1800.0):
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
