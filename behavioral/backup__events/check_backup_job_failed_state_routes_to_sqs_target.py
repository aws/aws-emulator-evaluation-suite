"""backup-job-failed-state-routes-to-sqs-target."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-job-failed-state-routes-to-sqs-target"
GROUP = "error-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Backup Job State Change event with State=FAILED (a job whose role holds no backup
    permissions) is routed by a content-filtered EventBridge rule to an SQS queue."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    queue_url, queue_arn = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"state": ["FAILED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["sqs-target"]))

    _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])

    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    # Trusts backup.amazonaws.com (so AWS Backup CAN assume it and create the job)
    # but has NO permissions attached at all, so the job fails during execution
    # with an authorization error -- a real, deterministic FAILED transition.
    noperm_role_arn = _create_noperm_backup_role(ctx)

    job_id = _start_backup_job_with_retry(
        ctx, backup, BackupVaultName=vault_name, ResourceArn=table_arn, IamRoleArn=noperm_role_arn
    )["BackupJobId"]

    messages = _poll_sqs_for_job(sqs, queue_url, job_id, timeout_s=300.0)
    assert len(messages) >= 1, "expected the FAILED event to be routed to the failure-handling queue"
    body = json.loads(messages[0]["Body"])
    assert body["detail"]["state"] == "FAILED"
    assert body["detail"]["backupJobId"] == job_id


# ===== helpers =====
def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-beh-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-beh-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name, BackupVaultTags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _cleanup_vault(backup, name))
    return name, resp["BackupVaultArn"]


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


def _create_noperm_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-beh-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role_arn


def _start_backup_job_with_retry(ctx, backup, **kwargs):
    """Retry StartBackupJob every 2 s while the new IAM role is not yet assumable by AWS Backup,
    to a 60 s deadline capped by the check's remaining budget."""
    from botocore.exceptions import ClientError

    timeout_s = 60.0
    left = ctx.time_left()
    if left is not None:
        timeout_s = min(timeout_s, left)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-beh-q-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
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


def _poll_sqs_for_job(sqs, queue_url: str, job_id: str, timeout_s: float = 300.0) -> list[dict[str, Any]]:
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

