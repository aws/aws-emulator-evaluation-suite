"""eventbridge-content-based-filtering-on-backup-vault-name."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-content-based-filtering-on-backup-vault-name"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pattern on detail.backupVaultName delivers only the backup job events of that vault and
    ignores those of a differently named vault, using real backup jobs in two vaults."""
    events = ctx.client("events")
    backup = ctx.client("backup")

    role_arn = _create_backup_role(ctx)
    target_vault_name, _target_vault_arn = _create_backup_vault(ctx)
    other_vault_name, _other_vault_arn = _create_backup_vault(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"backupVaultName": [target_vault_name]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    other_table_arn = _create_backup_table(ctx)
    other_job_id = _start_backup_job_with_retry(backup, other_vault_name, other_table_arn, role_arn)
    _assert_no_message_matching(ctx, queue["url"], lambda evt: _job_id_in(evt, other_job_id), duration_s=30.0)

    target_table_arn = _create_backup_table(ctx)
    target_job_id = _start_backup_job_with_retry(backup, target_vault_name, target_table_arn, role_arn)
    event = _wait_for_event_matching(
        ctx, queue["url"], lambda evt: _job_id_in(evt, target_job_id), timeout_s=120.0, interval_s=5.0
    )
    assert event["detail"]["backupVaultName"] == target_vault_name, (
        f"expected the delivered event's backupVaultName to be {target_vault_name!r}, "
        f"got {event['detail'].get('backupVaultName')!r}"
    )


def _job_id_in(evt: dict[str, Any], marker: str) -> bool:
    return evt.get("detail", {}).get("backupJobId") == marker


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_backup_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=2.0,
        description="table ACTIVE",
    )
    return ddb.describe_table(TableName=table_name)["Table"]["TableArn"]


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-vault-")
    resp = backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))
    return vault_name, resp["BackupVaultArn"]


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-evtq-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
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


def _start_backup_job_with_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0
) -> str:
    """IAM is eventually consistent: a freshly created role may not yet be assumable by the
    backup service. Poll the real condition (StartBackupJob succeeding) rather than sleeping
    a fixed duration."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"StartBackupJob never succeeded within {timeout_s}s: {last_exc}")


def _wait_for_event_matching(
    ctx, queue_url: str, match_fn, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s")


def _assert_no_message_matching(ctx, queue_url: str, match_fn, duration_s: float = 20.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                raise AssertionError(f"event for a differently-named vault was unexpectedly delivered: {body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
