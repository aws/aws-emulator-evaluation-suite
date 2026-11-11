"""backup-restore-job-event-drives-sqs-queue-message."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-restore-job-event-drives-sqs-queue-message"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed RestoreJob's EventBridge "Restore Job State Change" event, delivered to
    an SQS queue, carries the same restoreJobId and source-resource ARN as DescribeRestoreJob."""
    backup = ctx.client("backup")
    ddb = ctx.client("dynamodb")

    table_name, table_arn = _create_dynamodb_table(ctx)
    vault_name, vault_arn = _create_backup_vault(ctx)
    role_arn = _create_backup_role(ctx)

    rule_name, rule_arn = _create_rule(
        ctx, {"source": ["aws.backup"], "detail-type": ["Restore Job State Change"]}
    )
    queue_url, queue_arn = _create_queue_for_rule(ctx, [rule_arn])
    _bind_target(ctx, rule_name, queue_arn)

    job = _start_backup_job_with_retry(
        ctx, BackupVaultName=vault_name, ResourceArn=table_arn, IamRoleArn=role_arn
    )
    job_id = job["BackupJobId"]
    backup_desc = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id),
        lambda d: d["State"] in ("COMPLETED", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert backup_desc["State"] == "COMPLETED", f"backup job did not complete: {backup_desc}"
    recovery_point_arn = backup_desc["RecoveryPointArn"]

    restored_table_name = ctx.unique_name("sim2real-bkp-restored-")

    def _cleanup_restored_table() -> None:
        try:
            ddb.delete_table(TableName=restored_table_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "TableNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup_restored_table)

    restore = backup.start_restore_job(
        RecoveryPointArn=recovery_point_arn,
        Metadata={"targetTableName": restored_table_name},
        IamRoleArn=role_arn,
        ResourceType="DynamoDB",
    )
    restore_job_id = restore["RestoreJobId"]

    event = _poll_sqs_for_event(
        ctx,
        queue_url,
        lambda d: d.get("detail", {}).get("restoreJobId") == restore_job_id
        and d["detail"].get("status") in ("COMPLETED", "FAILED"),
        timeout_s=900,
    )
    detail = event["detail"]
    assert detail["status"] == "COMPLETED", f"restore job reported failure: {detail}"
    assert detail["sourceResourceArn"] == table_arn, (
        f"event sourceResourceArn {detail.get('sourceResourceArn')!r} != source table arn {table_arn!r}"
    )

    restore_desc = backup.describe_restore_job(RestoreJobId=restore_job_id)
    assert restore_desc["Status"] == "COMPLETED", (
        f"expected DescribeRestoreJob Status COMPLETED, got {restore_desc['Status']!r}"
    )
    assert restore_desc["RestoreJobId"] == detail["restoreJobId"], (
        f"DescribeRestoreJob RestoreJobId {restore_desc['RestoreJobId']!r} != "
        f"event restoreJobId {detail['restoreJobId']!r}"
    )
    assert restore_desc["CreatedResourceArn"] == detail["createdResourceArn"], (
        f"DescribeRestoreJob CreatedResourceArn {restore_desc['CreatedResourceArn']!r} != "
        f"event createdResourceArn {detail['createdResourceArn']!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_dynamodb_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-bkp-tbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-bkp-vault-")
    arn = backup.create_backup_vault(BackupVaultName=name)["BackupVaultArn"]

    def _cleanup() -> None:
        try:
            points = backup.list_recovery_points_by_backup_vault(BackupVaultName=name).get(
                "RecoveryPoints", []
            )
            for p in points:
                try:
                    backup.delete_recovery_point(
                        BackupVaultName=name, RecoveryPointArn=p["RecoveryPointArn"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            for _ in range(20):
                remaining = backup.list_recovery_points_by_backup_vault(
                    BackupVaultName=name
                ).get("RecoveryPoints", [])
                if not remaining:
                    break
                time.sleep(5)
            backup.delete_backup_vault(BackupVaultName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name, arn


def _create_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-bkp-role-")
    trust = json.dumps(
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
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    managed_policies = (
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    )
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            for policy_arn in managed_policies:
                try:
                    iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _create_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-bkp-rule-")
    arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")[
        "RuleArn"
    ]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name, arn


def _create_queue_for_rule(ctx, rule_arns: list[str]) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-bkp-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    source_arn_condition = rule_arns[0] if len(rule_arns) == 1 else rule_arns
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn_condition}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _bind_target(ctx, rule_name: str, target_arn: str, target_id: str = "target-1") -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_sqs_for_event(ctx, queue_url: str, predicate, timeout_s: float = 600.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except ValueError:
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body is not None and predicate(body):
                return body
    raise AssertionError(f"expected event not observed within {timeout_s}s")


def _start_backup_job_with_retry(ctx, **kwargs):
    """Retry StartBackupJob every 2 s while the new IAM role is not yet assumable by AWS Backup,
    to a 60 s deadline capped by the check's remaining budget."""
    from botocore.exceptions import ClientError

    backup = ctx.client("backup")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
