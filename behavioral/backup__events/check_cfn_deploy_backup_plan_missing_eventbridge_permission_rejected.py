"""cfn-deploy-backup-plan-missing-eventbridge-permission-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-backup-plan-missing-eventbridge-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]

_BACKUP_SERVICE_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
)


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Of two CFN-deployed Scheduler schedules targeting backup:StartBackupJob, the one whose
    role lacks that permission never produces a backup job, while the sibling with the
    permission does: the missing permission is enforced, not every invocation refused.
    """
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    caller_arn = f"arn:aws:iam::{account}:root"

    table_arn_broken, table_arn_working, backup_role_arn, vault_name = _create_backup_fixtures(ctx)

    broken_role_name = ctx.unique_name("sim2real-xsvc-brokenrole-")
    working_role_name = ctx.unique_name("sim2real-xsvc-workrole-")
    broken_role_arn = f"arn:aws:iam::{account}:role/{broken_role_name}"
    working_role_arn = f"arn:aws:iam::{account}:role/{working_role_name}"
    schedule_broken_name = ctx.unique_name("sim2real-xsvc-schbroken-")
    schedule_working_name = ctx.unique_name("sim2real-xsvc-schwork-")

    schedule_at_dt = (datetime.now(timezone.utc) + timedelta(minutes=4)).replace(microsecond=0)
    schedule_at_expr = f"at({schedule_at_dt.strftime('%Y-%m-%dT%H:%M:%S')})"

    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                # Lets the check itself assume the role directly to capture the exact
                # denial error code synchronously — it grants NO backup permission and so
                # does not touch the one thing under test.
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": "sts:AssumeRole",
            },
        ],
    }

    def _input_for(table_arn: str, schedule_name: str) -> str:
        return json.dumps(
            {
                "BackupVaultName": vault_name,
                "ResourceArn": table_arn,
                "IamRoleArn": backup_role_arn,
                "IdempotencyToken": schedule_name,
            }
        )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "BrokenRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": broken_role_name,
                    "AssumeRolePolicyDocument": trust_doc,
                    "Policies": [
                        {
                            "PolicyName": "PassRoleOnly",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    # Deliberately missing backup:StartBackupJob — the one
                                    # thing under test.
                                    {
                                        "Effect": "Allow",
                                        "Action": "iam:PassRole",
                                        "Resource": backup_role_arn,
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "WorkingRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": working_role_name,
                    "AssumeRolePolicyDocument": trust_doc,
                    "Policies": [
                        {
                            "PolicyName": "StartBackupJobAndPassRole",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": "backup:StartBackupJob", "Resource": "*"},
                                    {
                                        "Effect": "Allow",
                                        "Action": "iam:PassRole",
                                        "Resource": backup_role_arn,
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "ScheduleBroken": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": schedule_broken_name,
                    "ScheduleExpression": schedule_at_expr,
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "State": "ENABLED",
                    "Target": {
                        "Arn": "arn:aws:scheduler:::aws-sdk:backup:startBackupJob",
                        "RoleArn": broken_role_arn,
                        "Input": _input_for(table_arn_broken, schedule_broken_name),
                    },
                },
                "DependsOn": "BrokenRole",
            },
            "ScheduleWorking": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": schedule_working_name,
                    "ScheduleExpression": schedule_at_expr,
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "State": "ENABLED",
                    "Target": {
                        "Arn": "arn:aws:scheduler:::aws-sdk:backup:startBackupJob",
                        "RoleArn": working_role_arn,
                        "Input": _input_for(table_arn_working, schedule_working_name),
                    },
                },
                "DependsOn": "WorkingRole",
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))
    # the broken schedule is moved first, so the working one is never due before it
    schedule_at_dt = _reschedule(ctx, [schedule_broken_name, schedule_working_name])

    # (a) The exact denial: directly exercise BrokenRole's permission boundary rather than
    # waiting on the async schedule (which never surfaces an error to the caller). A
    # bounded retry rides out IAM role propagation lag before STS can rely on the role —
    # the role exists (CFN reached CREATE_COMPLETE) but has not yet propagated everywhere.
    def _assume_broken_role():
        try:
            return sts.assume_role(RoleArn=broken_role_arn, RoleSessionName="sim2real-verify")[
                "Credentials"
            ]
        except ClientError:
            return None

    assumed = _poll_until(
        _assume_broken_role,
        lambda c: c is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description="assume BrokenRole after IAM propagation",
    )
    broken_backup = ctx.client(
        "backup",
        creds={
            "aws_access_key_id": assumed["AccessKeyId"],
            "aws_secret_access_key": assumed["SecretAccessKey"],
            "aws_session_token": assumed["SessionToken"],
        },
    )
    code, message = _client_error(
        lambda: broken_backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn=table_arn_broken,
            IamRoleArn=backup_role_arn,
            IdempotencyToken=ctx.unique_name("idem-"),
        )
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException from BrokenRole (missing backup:StartBackupJob), got {code!r}"
    )
    vault_arn = f"arn:aws:backup:{ctx.region}:{account}:backup-vault:{vault_name}"
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{broken_role_name}/sim2real-verify is not "
        f"authorized to perform: backup:StartBackupJob on resource: {vault_arn} because no "
        "identity-based policy allows the backup:StartBackupJob action"
    )
    assert message == expected_message, (
        f"expected the exact denial message {expected_message!r}, got {message!r}"
    )

    # The schedule cannot fire before its "at" time, so the poll deadline below already
    # covers that wait — it is a bounded retry with a stated deadline, not a blind sleep.
    remaining = max((schedule_at_dt - datetime.now(timezone.utc)).total_seconds(), 0.0)

    backup = ctx.client("backup")

    # (c) Positive control in this same file: the sibling schedule with the permission
    # present must actually succeed.
    def _working_job():
        jobs = backup.list_backup_jobs(ByResourceArn=table_arn_working).get("BackupJobs", [])
        return jobs[0] if jobs else None

    working_job = _poll_until(
        _working_job,
        lambda j: j is not None,
        timeout_s=remaining + 180.0,
        interval_s=2.0,
        description="positive-control backup job via WorkingRole",
    )
    assert working_job["ResourceArn"] == table_arn_working, (
        f"expected the positive-control backup job to target {table_arn_working!r}, "
        f"got {working_job['ResourceArn']!r}"
    )

    # (b) The effect is absent: even after the working schedule has clearly had time to
    # fire, the broken one must never have produced a job.
    broken_jobs = backup.list_backup_jobs(ByResourceArn=table_arn_broken).get("BackupJobs", [])
    assert broken_jobs == [], (
        f"expected no backup jobs via BrokenRole (missing permission), got {broken_jobs!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _client_error(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError `fn` raises; raise if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _create_backup_fixtures(ctx) -> tuple[str, str, str, str]:
    """Two DynamoDB tables (one per schedule, so job listings cleanly attribute to
    broken vs. working), a shared vault, and the AWS-Backup service role. Returns
    (table_arn_broken, table_arn_working, backup_role_arn, vault_name)."""
    dynamodb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    backup = ctx.client("backup")

    def _make_table() -> str:
        name = ctx.unique_name("sim2real-xsvc-bkptbl-")
        dynamodb.create_table(
            TableName=name,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        )
        ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=name))
        return dynamodb.describe_table(TableName=name)["Table"]["TableArn"]

    table_arn_broken = _make_table()
    table_arn_working = _make_table()

    vault_name = ctx.unique_name("sim2real-xsvc-bkpvault-")
    backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _delete_vault(ctx, vault_name))

    role_name = ctx.unique_name("sim2real-xsvc-bkprole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "backup.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BACKUP_SERVICE_POLICY)

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_BACKUP_SERVICE_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    def _policy_attached():
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        except ClientError:
            return False
        return any(p["PolicyArn"] == _BACKUP_SERVICE_POLICY for p in attached)

    _poll_until(
        _policy_attached,
        lambda ok: ok,
        timeout_s=30.0,
        interval_s=3.0,
        description=f"IAM role {role_name} policy attachment visible",
    )
    return table_arn_broken, table_arn_working, role_arn, vault_name


def _delete_vault(ctx, vault_name: str) -> None:
    backup = ctx.client("backup")

    def _rps():
        try:
            return backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get(
                "RecoveryPoints", []
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

    # A still-running backup job keeps the vault refused, then leaves a recovery point to remove.
    deadline = time.monotonic() + 300.0
    while True:
        rps = _rps()
        for rp in rps:
            try:
                backup.delete_recovery_point(
                    BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException" and not _refused_busy(exc):
                    raise
        if not rps:
            try:
                backup.delete_backup_vault(BackupVaultName=vault_name)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                if not _refused_busy(exc) or time.monotonic() >= deadline:
                    raise
        elif time.monotonic() >= deadline:
            raise AssertionError(f"vault {vault_name} still holds recovery points after 300 s")
        time.sleep(2.0)


def _refused_busy(exc: ClientError) -> bool:
    """The refusals AWS Backup returns while a job or a recovery point deletion is in flight."""
    err = exc.response["Error"]
    msg = err.get("Message", "")
    return err["Code"] == "InvalidRequestException" and (
        "active Backup Jobs" in msg or "already started the deletion" in msg
    )


def _reschedule(ctx, names: list[str]) -> datetime:
    """Move the deployed one-time schedules to fire 60 s from now, so the wait does not carry
    the margin the template leaves for the deploy itself; returns the new fire time."""
    scheduler = ctx.client("scheduler")
    at_dt = (datetime.now(timezone.utc) + timedelta(seconds=60)).replace(microsecond=0)
    for name in names:
        current = scheduler.get_schedule(Name=name)
        scheduler.update_schedule(
            Name=name,
            GroupName=current["GroupName"],
            ScheduleExpression=f"at({at_dt.strftime('%Y-%m-%dT%H:%M:%S')})",
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow=current["FlexibleTimeWindow"],
            State=current["State"],
            Target=current["Target"],
        )
    return at_dt


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
