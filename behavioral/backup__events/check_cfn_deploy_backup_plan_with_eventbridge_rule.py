"""cfn-deploy-backup-plan-with-eventbridge-rule."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-backup-plan-with-eventbridge-rule"
GROUP = "deployment-order"
SERVICES = ["backup", "events"]

_BACKUP_SERVICE_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
)


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN-deployed Scheduler schedule whose universal target is backup:StartBackupJob fires
    and produces a completed backup job for the deployed table with the deployed role, so
    the deployed chain works end to end, not just CREATE_COMPLETE.
    """
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    table_name = ctx.unique_name("sim2real-xsvc-bkptbl-")
    vault_name = ctx.unique_name("sim2real-xsvc-bkpvault-")
    plan_name = ctx.unique_name("sim2real-xsvc-bkpplan-")
    backup_role_name = ctx.unique_name("sim2real-xsvc-bkprole-")
    scheduler_role_name = ctx.unique_name("sim2real-xsvc-schrole-")
    schedule_name = ctx.unique_name("sim2real-xsvc-sched-")

    table_arn = f"arn:aws:dynamodb:{region}:{account}:table/{table_name}"
    backup_role_arn = f"arn:aws:iam::{account}:role/{backup_role_name}"
    scheduler_role_arn = f"arn:aws:iam::{account}:role/{scheduler_role_name}"

    # AWS Scheduler docs: "your target might be invoked up to a minute following your
    # specified start time" — give CFN deploy + that latency a generous margin.
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
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                },
            },
            "Vault": {
                "Type": "AWS::Backup::BackupVault",
                "Properties": {"BackupVaultName": vault_name},
            },
            "Plan": {
                "Type": "AWS::Backup::BackupPlan",
                "Properties": {
                    "BackupPlan": {
                        "BackupPlanName": plan_name,
                        "BackupPlanRule": [
                            {
                                "RuleName": "far-future-noop",
                                "TargetBackupVault": vault_name,
                                # Far-future schedule: this plan's OWN cron must never fire
                                # during the check — only the Scheduler-driven call below is
                                # under test.
                                "ScheduleExpression": "cron(0 5 1 1 ? 2099)",
                                "StartWindowMinutes": 60,
                                "CompletionWindowMinutes": 120,
                            }
                        ],
                    }
                },
                "DependsOn": "Vault",
            },
            "BackupServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": backup_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "backup.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [_BACKUP_SERVICE_POLICY],
                },
            },
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
                "DependsOn": ["SchedulerExecRole", "Table", "Vault"],
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))
    ctx.on_cleanup(lambda: _delete_all_recovery_points(ctx, vault_name))
    schedule_at_dt = _reschedule(ctx, [schedule_name])

    backup = ctx.client("backup")

    def _job():
        jobs = backup.list_backup_jobs(ByResourceArn=table_arn).get("BackupJobs", [])
        return jobs[0] if jobs else None

    # The schedule cannot fire before its "at" time — that deadline is folded into this
    # poll's timeout (rather than a blind sleep first) so the wait is a single bounded
    # retry with a stated deadline, not an unconditional sleep.
    wait_for_fire_s = max((schedule_at_dt - datetime.now(timezone.utc)).total_seconds(), 0.0)
    job = _poll_until(
        _job,
        lambda j: j is not None,
        timeout_s=wait_for_fire_s + 180.0,
        interval_s=2.0,
        description="backup job created by the deployed schedule",
    )

    job = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job["BackupJobId"]),
        lambda j: j["State"] in {"COMPLETED", "FAILED", "ABORTED", "EXPIRED"},
        timeout_s=300.0,
        interval_s=10.0,
        description="backup job reaching a terminal state",
    )
    assert job["State"] == "COMPLETED", f"backup job ended in {job['State']}"
    assert job["IamRoleArn"] == backup_role_arn, (
        f"expected IamRoleArn {backup_role_arn!r}, got {job['IamRoleArn']!r}"
    )
    assert job["ResourceArn"] == table_arn, (
        f"expected ResourceArn {table_arn!r}, got {job['ResourceArn']!r}"
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
        try:
            events = cfn.describe_stack_events(StackName=name)["StackEvents"]
            reasons = "; ".join(
                f"{e['LogicalResourceId']}:{e['ResourceStatus']}:{e.get('ResourceStatusReason', '')}"
                for e in events
                if e.get("ResourceStatusReason")
            )
        except ClientError:
            reasons = "<unavailable>"
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {reasons}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _delete_all_recovery_points(ctx, vault_name: str) -> None:
    """AWS::Backup::BackupVault can only be deleted (by the stack teardown) once it is
    empty — a completed job leaves a recovery point behind, so remove those first."""
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

    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        rps = _rps()
        if not rps:
            return
        for rp in rps:
            try:
                backup.delete_recovery_point(
                    BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException" and not _deleting(exc):
                    raise
        time.sleep(2.0)
    raise AssertionError(f"vault {vault_name} still holds recovery points 240 s after DeleteRecoveryPoint")


def _deleting(exc: ClientError) -> bool:
    """A recovery point whose deletion already started is refused again until it is gone."""
    err = exc.response["Error"]
    return err["Code"] == "InvalidRequestException" and "already started the deletion" in err.get("Message", "")


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
