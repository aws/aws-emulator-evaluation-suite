"""backup-continuous-backup-event-delivered-to-sns-via-eventbridge."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-continuous-backup-event-delivered-to-sns-via-eventbridge"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Recovery Point State Change event for a continuously backed-up DynamoDB table is routed
    by an EventBridge rule to an SNS topic, and the subscribed SQS queue receives it with the
    recovery point's resourceArn and COMPLETED status."""
    backup = ctx.client("backup")
    sns = ctx.client("sns")

    table_name, table_arn = _create_dynamodb_table_with_pitr(ctx)
    vault_name, vault_arn = _create_backup_vault(ctx)
    role_arn = _create_backup_role(ctx)

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-bkp-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    rule_name, rule_arn = _create_rule(
        ctx, {"source": ["aws.backup"], "detail-type": ["Recovery Point State Change"]}
    )
    _authorize_topic_for_rule(ctx, topic_arn, rule_arn)
    _bind_target(ctx, rule_name, topic_arn)

    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    job_id, backup_desc = _run_backup_job_to_completion(
        ctx, vault_name, table_arn, role_arn
    )
    recovery_point_arn = backup_desc["RecoveryPointArn"]

    recovery_points = backup.list_recovery_points_by_backup_vault(
        BackupVaultName=vault_name
    )["RecoveryPoints"]
    assert any(p["RecoveryPointArn"] == recovery_point_arn for p in recovery_points), (
        f"expected recovery point {recovery_point_arn!r} in vault {vault_name!r}, "
        f"got {[p['RecoveryPointArn'] for p in recovery_points]!r}"
    )

    # Terminal read is at the consumer (SQS, behind the SNS topic EventBridge publishes
    # to) — the producer-side reads above only establish that the job itself completed.
    envelope = _poll_sqs_for_notification(
        ctx,
        queue_url,
        lambda evt: evt.get("detail", {}).get("resourceArn") == table_arn
        and evt["detail"].get("status") in ("COMPLETED", "PARTIAL"),
        timeout_s=300,
    )
    assert envelope["TopicArn"] == topic_arn, (
        f"expected notification TopicArn {topic_arn!r}, got {envelope['TopicArn']!r}"
    )
    inner = json.loads(envelope["Message"])
    assert inner["detail"]["resourceArn"] == table_arn, (
        f"expected event resourceArn {table_arn!r}, got {inner['detail']['resourceArn']!r}"
    )
    assert inner["detail"]["status"] == "COMPLETED", (
        f"expected event status 'COMPLETED', got {inner['detail']['status']!r}"
    )
    assert inner["detail"]["backupVaultArn"] == vault_arn, (
        f"expected event backupVaultArn {vault_arn!r}, got {inner['detail']['backupVaultArn']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_dynamodb_table_with_pitr(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-bkp-tbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    _enable_continuous_backups_with_retry(ddb, name)
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _enable_continuous_backups_with_retry(ddb, table_name: str, timeout_s: float = 120.0) -> None:
    """A table that just reached ACTIVE is not yet ready for UpdateContinuousBackups: real
    DynamoDB answers ContinuousBackupsUnavailableException ("Backups are being enabled for
    the table ... Please retry later") for a short warm-up window. Retry that specific,
    named condition; any other error is a real defect and propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ContinuousBackupsUnavailableException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-bkp-vault-")
    arn = backup.create_backup_vault(
        BackupVaultName=name, BackupVaultTags={"sim2real": CHECK}
    )["BackupVaultArn"]

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
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
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
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name, arn


def _authorize_topic_for_rule(ctx, topic_arn: str, rule_arn: str) -> None:
    sns = ctx.client("sns")
    existing = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get("Policy")
    policy_doc = json.loads(existing) if existing else {"Version": "2012-10-17", "Statement": []}
    policy_doc["Statement"].append(
        {
            "Sid": "AllowEventBridge",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }
    )
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy_doc)
    )


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-bkp-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSns",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _bind_target(ctx, rule_name: str, target_arn: str, target_id: str = "target-1") -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_sqs_for_notification(ctx, queue_url: str, predicate, timeout_s: float = 300.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                envelope = json.loads(m["Body"])
                inner = json.loads(envelope["Message"])
            except (ValueError, KeyError):
                continue
            if predicate(inner):
                return envelope
    raise AssertionError(f"expected SNS notification not observed within {timeout_s}s")


def _start_backup_job_with_retry(ctx, **kwargs):
    """StartBackupJob, retried every 2 s for up to 90 s on the InvalidParameterValueException a
    just-created role draws until backup.amazonaws.com can assume it; anything else raises."""
    backup = ctx.client("backup")
    timeout_s = 90.0
    left = ctx.time_left()
    if left is not None:
        timeout_s = min(timeout_s, left)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "InvalidParameterValueException"
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _run_backup_job_to_completion(
    ctx, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 300.0
) -> tuple[str, dict]:
    """A DynamoDB table freshly enrolled in continuous backups needs a brief AWS-side
    warm-up: StartBackupJob succeeds and returns a job id, but the job then goes FAILED
    with a StatusMessage saying backups are still being enabled for the table. Retry the
    whole start+wait cycle while that specific, named condition holds; any other terminal
    state fails immediately."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    while True:
        job = _start_backup_job_with_retry(
            ctx, BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
        )
        job_id = job["BackupJobId"]
        final_job = _poll_until(
            lambda: backup.describe_backup_job(BackupJobId=job_id),
            lambda d: d["State"] in ("COMPLETED", "FAILED", "ABORTED"),
            timeout_s=900,
            interval_s=15,
        )
        if final_job["State"] == "COMPLETED":
            return job_id, final_job
        message = final_job.get("StatusMessage") or ""
        if (
            final_job["State"] == "FAILED"
            and "being enabled" in message
            and time.monotonic() < deadline
        ):
            time.sleep(2.0)
            continue
        raise AssertionError(f"backup job {job_id} did not complete: {final_job}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
