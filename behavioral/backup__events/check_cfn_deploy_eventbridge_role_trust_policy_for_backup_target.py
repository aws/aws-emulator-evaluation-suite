"""cfn-deploy-eventbridge-role-trust-policy-for-backup-target."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-role-trust-policy-for-backup-target"
GROUP = "deployment-order"
SERVICES = ["backup", "events"]

_BACKUP_SERVICE_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
)


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN-deployed Scheduler execution role has exactly the scheduler.amazonaws.com trust
    document, and the deployed schedule assumes it to invoke backup:StartBackupJob end to end.
    """
    iam = ctx.client("iam")
    backup = ctx.client("backup")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    table_arn, backup_role_arn, vault_name = _create_backup_fixture(ctx)

    scheduler_role_name = ctx.unique_name("sim2real-xsvc-schrole-")
    scheduler_role_arn = f"arn:aws:iam::{account}:role/{scheduler_role_name}"
    schedule_name = ctx.unique_name("sim2real-xsvc-sched-")

    schedule_at_dt = (datetime.now(timezone.utc) + timedelta(minutes=4)).replace(microsecond=0)
    schedule_at_expr = f"at({schedule_at_dt.strftime('%Y-%m-%dT%H:%M:%S')})"

    target_input = json.dumps(
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
            "SchedulerExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": scheduler_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "scheduler.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "InvokeStartBackupJob",
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
            "Schedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": schedule_name,
                    "ScheduleExpression": schedule_at_expr,
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "State": "ENABLED",
                    "Target": {
                        "Arn": "arn:aws:scheduler:::aws-sdk:backup:startBackupJob",
                        "RoleArn": scheduler_role_arn,
                        "Input": target_input,
                    },
                },
                "DependsOn": "SchedulerExecRole",
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))
    schedule_at_dt = _reschedule(ctx, [schedule_name])

    # The deployed role's trust document must be exactly the one we asked for — not just
    # that GetRole succeeds.
    trust = iam.get_role(RoleName=scheduler_role_name)["Role"]["AssumeRolePolicyDocument"]
    assert trust["Statement"] == [
        {
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ], f"deployed trust policy statement(s) {trust['Statement']!r}, expected exactly the scheduler.amazonaws.com trust we templated"

    # No separate wait for the schedule's fire time: the poll below is already bounded by a
    # deadline that covers it, so there is nothing left for an unconditional sleep to do.
    remaining = (schedule_at_dt - datetime.now(timezone.utc)).total_seconds()

    def _job():
        jobs = backup.list_backup_jobs(ByResourceArn=table_arn).get("BackupJobs", [])
        return jobs[0] if jobs else None

    job = _poll_until(
        _job,
        lambda j: j is not None,
        timeout_s=max(remaining, 0.0) + 180.0,
        interval_s=2.0,
        description="backup job created by the deployed schedule using the deployed role",
    )
    assert job["IamRoleArn"] == backup_role_arn, (
        f"backup job used role {job['IamRoleArn']!r}, expected the deployed backup service role {backup_role_arn!r}"
    )
    assert job["ResourceArn"] == table_arn, (
        f"backup job targeted resource {job['ResourceArn']!r}, expected {table_arn!r}"
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


def _create_backup_fixture(ctx) -> tuple[str, str, str]:
    """Pre-create (outside CFN, via plain boto3) the DynamoDB table, the AWS-Backup
    service role, and the vault the CFN-deployed schedule will target. Returns
    (table_arn, backup_role_arn, vault_name)."""
    dynamodb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    backup = ctx.client("backup")

    table_name = ctx.unique_name("sim2real-xsvc-bkptbl-")
    dynamodb.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=table_name))
    table_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]

    vault_name = ctx.unique_name("sim2real-xsvc-bkpvault-")
    backup.create_backup_vault(BackupVaultName=vault_name, BackupVaultTags={"sim2real": CHECK})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    # No fixed propagation sleep: the schedule this role is passed to is always created (and
    # fires) at least ~4 minutes later in run(), which is ample time for IAM to propagate — and
    # that firing is itself bounded by a poll with a real deadline, so a blind sleep here would
    # only ever pad wall-clock time, never correctness.
    return table_arn, role_arn, vault_name


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
