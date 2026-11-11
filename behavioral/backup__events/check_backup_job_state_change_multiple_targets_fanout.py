"""backup-job-state-change-multiple-targets-fanout."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-job-state-change-multiple-targets-fanout"
GROUP = "fanout"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A native Backup Job State Change event fans out from one EventBridge rule to two targets.

    An SQS queue target and an SNS topic (raw delivery to a second queue) both get the job's event.
    """
    events = ctx.client("events")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["aws.backup"], "detail-type": ["Backup Job State Change"]}
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, Force=True))

    direct_queue = _create_events_queue(ctx, rule_arn)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    topic_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(topic_policy))

    fanout_queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-fanq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fanout_queue_url))
    fanout_queue_arn = sqs.get_queue_attributes(QueueUrl=fanout_queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sub_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": fanout_queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=fanout_queue_url, Attributes={"Policy": json.dumps(sub_policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=fanout_queue_arn, Attributes={"RawMessageDelivery": "true"}
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "sqs-target", "Arn": direct_queue["arn"]},
            {"Id": "sns-target", "Arn": topic_arn},
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sqs-target", "sns-target"], Force=True))

    # EventBridge does not deliver a customer PutEvents entry with a reserved "aws.*" source, so a
    # real backup job is driven to emit the event.
    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)

    def _start():
        return backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn=table_arn,
            IamRoleArn=backup_role_arn,
            IdempotencyToken=str(uuid.uuid4()),
        )

    job_id = _retry_until_success(_start, retry_codes={"InvalidParameterValueException"})["BackupJobId"]

    direct_body, fanout_body = _wait_for_fanout(sqs, direct_queue["url"], fanout_queue_url, job_id, timeout_s=220.0)

    assert direct_body["source"] == "aws.backup", (
        f"direct SQS target: expected source 'aws.backup', got {direct_body.get('source')!r}"
    )
    assert direct_body["detail"]["backupJobId"] == job_id, (
        f"direct SQS target: expected backupJobId {job_id!r}, got {direct_body['detail'].get('backupJobId')!r}"
    )
    assert fanout_body["detail-type"] == "Backup Job State Change", (
        f"SNS raw-delivery target: expected detail-type 'Backup Job State Change' preserved through the "
        f"SNS hop, got {fanout_body.get('detail-type')!r}"
    )
    assert fanout_body["detail"]["backupJobId"] == job_id, (
        f"SNS raw-delivery target: expected backupJobId {job_id!r}, got {fanout_body['detail'].get('backupJobId')!r}"
    )

    # The vault deletes only once the job has settled and its recovery point is gone, so the job
    # is drained here, inside the check's budget, rather than in the teardown.
    _wait_job_settled(ctx, backup, job_id)


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evtq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-fanout-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-fanout-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name)
    ctx.on_cleanup(lambda: _cleanup_vault(backup, name))
    return name, resp["BackupVaultArn"]


def _cleanup_vault(backup, vault_name: str) -> None:
    """Teardown: empty and delete the vault, retrying for 45 s (inside the 60 s cleanup budget)
    while a recovery point is still being deleted (InvalidRequestException); raise at the deadline.
    The check body drains the backup job first, so only the recovery point's delete is waited on."""
    deadline = time.monotonic() + 45
    while True:
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
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


_JOB_SETTLED = {"COMPLETED", "FAILED", "ABORTED", "EXPIRED", "PARTIAL"}


def _wait_job_settled(ctx, backup, job_id: str, timeout_s: float = 1200.0) -> None:
    """Poll the backup job every 2 s until it reaches a terminal state (a DynamoDB on-demand
    backup runs for minutes), bounded by the check's remaining budget; raise naming the last
    state at the deadline."""
    left = ctx.time_left()
    if left is not None:
        timeout_s = min(timeout_s, max(0.0, left - 30.0))
    deadline = time.monotonic() + timeout_s
    state = None
    while True:
        state = backup.describe_backup_job(BackupJobId=job_id)["State"]
        if state in _JOB_SETTLED:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"backup job {job_id} still {state} after {timeout_s:.0f}s; its vault cannot be deleted"
            )
        time.sleep(2)


def _create_backup_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fanout-bkuprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, [policy_arn]))
    return role_arn


def _retry_until_success(fn: Callable[[], Any], retry_codes: set[str], timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc = None
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


def _wait_for_fanout(
    sqs, direct_queue_url: str, fanout_queue_url: str, job_id: str, timeout_s: float = 220.0
) -> tuple[dict[str, Any], dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    direct_body: dict[str, Any] | None = None
    fanout_body: dict[str, Any] | None = None
    while time.monotonic() < deadline and (direct_body is None or fanout_body is None):
        if direct_body is None:
            direct_body = _receive_matching(sqs, direct_queue_url, job_id)
        if fanout_body is None:
            fanout_body = _receive_matching(sqs, fanout_queue_url, job_id)
    if direct_body is None:
        raise AssertionError(
            f"direct SQS target never received the Backup Job State Change event for job {job_id} within {timeout_s}s"
        )
    if fanout_body is None:
        raise AssertionError(
            f"SNS-fanout SQS target never received the Backup Job State Change event for job {job_id} within {timeout_s}s"
        )
    return direct_body, fanout_body


def _receive_matching(sqs, queue_url: str, job_id: str) -> dict[str, Any] | None:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            continue
        if body.get("detail", {}).get("backupJobId") == job_id:
            return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
