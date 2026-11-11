"""cli-create-backup-plan-and-verify-eventbridge-rule-target."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-create-backup-plan-and-verify-eventbridge-rule-target"
GROUP = "workflow"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Backup vault, plan and EventBridge rule/target created with the CLI route a native
    Backup Job State Change event for an on-demand DynamoDB backup job to the SQS target.
    """
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    table_name, table_arn = _create_table(ctx)
    backup_svc_role_arn = _create_backup_service_role(ctx)
    queue_url, queue_arn = _create_queue(ctx)

    vault_name = ctx.unique_name("sim2real-beh-vault-")
    _run_aws(ctx, ["backup", "create-backup-vault", "--backup-vault-name", vault_name])
    ctx.on_cleanup(lambda: _cleanup_vault(ctx.client("backup"), vault_name))

    plan_name = ctx.unique_name("sim2real-beh-plan-")
    plan_body = {
        "BackupPlanName": plan_name,
        "Rules": [
            {
                "RuleName": "daily",
                "TargetBackupVaultName": vault_name,
                "ScheduleExpression": "cron(0 5 * * ? *)",
                "StartWindowMinutes": 60,
                "CompletionWindowMinutes": 120,
            }
        ],
    }
    plan_out = json.loads(
        _run_aws(ctx, ["backup", "create-backup-plan", "--backup-plan", json.dumps(plan_body)])
    )
    plan_id = plan_out["BackupPlanId"]
    ctx.on_cleanup(lambda: ctx.client("backup").delete_backup_plan(BackupPlanId=plan_id))

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {"source": ["aws.backup"], "detail-type": ["Backup Job State Change"]}
    rule_out = json.loads(
        _run_aws(ctx, ["events", "put-rule", "--name", rule_name, "--event-pattern", json.dumps(pattern)])
    )
    rule_arn = rule_out["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(ctx.client("events"), rule_name, ["sqs-target"]))

    _allow_eventbridge_to_send(ctx.client("sqs"), queue_url, queue_arn, rule_arn)
    _run_aws(
        ctx,
        [
            "events",
            "put-targets",
            "--rule",
            rule_name,
            "--targets",
            json.dumps([{"Id": "sqs-target", "Arn": queue_arn}]),
        ],
    )

    backup = ctx.client("backup")

    def _start():
        return backup.start_backup_job(
            BackupVaultName=vault_name, ResourceArn=table_arn, IamRoleArn=backup_svc_role_arn
        )

    job_out = _retry_until_success(_start, retry_codes={"InvalidParameterValueException"})
    real_job_id = job_out["BackupJobId"]

    messages = _poll_sqs_for_job(ctx.client("sqs"), queue_url, real_job_id, timeout_s=120.0)
    assert messages, f"expected the native state-change event for job {real_job_id} to reach the SQS target"
    body = json.loads(messages[0]["Body"])
    assert body["source"] == "aws.backup", f"expected source aws.backup, got {body['source']!r}"
    assert body["detail-type"] == "Backup Job State Change", (
        f"expected detail-type 'Backup Job State Change', got {body['detail-type']!r}"
    )
    assert body["detail"]["backupJobId"] == real_job_id, (
        f"expected event to correlate with job {real_job_id}, got {body['detail']['backupJobId']!r}"
    )


def _run_aws(ctx, args: list[str]) -> str:
    cmd = ["aws", "--region", ctx.region, "--output", "json"] + args
    result = subprocess.run(cmd, env=ctx.subprocess_env(), capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError(f"aws CLI command failed: {' '.join(cmd)}\nstderr:\n{result.stderr}")
    return result.stdout or "{}"


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-beh-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_backup_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-beh-bkuprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, [policy_arn]))
    return role_arn


def _retry_until_success(fn, retry_codes: set[str], timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    """Bounded retry for calls made against a just-created IAM role: AWS Backup
    rejects the role with InvalidParameterValueException until the role has
    propagated, which is eventual and not on a fixed schedule."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_role(iam, role_name: str, managed_policy_arns: list[str]) -> None:
    for arn in managed_policy_arns:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-beh-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_eventbridge_to_send(sqs, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _delete_rule(events, rule_name: str, target_ids: list[str]) -> None:
    try:
        if target_ids:
            events.remove_targets(Rule=rule_name, Ids=target_ids, Force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        events.delete_rule(Name=rule_name, Force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_vault(backup, vault_name: str) -> None:
    try:
        rps = backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get(
            "RecoveryPoints", []
        )
        for rp in rps:
            try:
                backup.delete_recovery_point(
                    BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        backup.delete_backup_vault(BackupVaultName=vault_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_sqs_for_job(sqs, queue_url: str, job_id: str, timeout_s: float = 120.0) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            if body.get("detail", {}).get("backupJobId") == job_id:
                return [m]
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
