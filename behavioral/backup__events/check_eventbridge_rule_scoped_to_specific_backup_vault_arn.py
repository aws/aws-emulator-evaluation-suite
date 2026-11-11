"""eventbridge-rule-scoped-to-specific-backup-vault-arn."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-scoped-to-specific-backup-vault-arn"
GROUP = "arn-resolution"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule filtering on one backup vault ARN in the event detail delivers the Backup Job State
    Change event of a real job in that vault and suppresses the same event for a job in another
    vault."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    # Separate tables for the two jobs: AWS Backup rejects a second on-demand job
    # against a resource that already has one running ("Backup job failed because
    # there was a running job for the same resource"), which would make the two
    # jobs' starts non-concurrent no matter how this check schedules them.
    target_table_name, target_table_arn = _create_table(ctx)
    other_table_name, other_table_arn = _create_table(ctx)
    backup_role_arn = _create_backup_service_role(ctx)
    target_vault_name, target_vault_arn = _create_vault(ctx)
    other_vault_name, other_vault_arn = _create_vault(ctx)

    queue_url, queue_arn = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"backupVaultArn": [target_vault_arn]},
    }
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["sqs-target"]))

    _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])

    # Start both real jobs close together, against different tables so neither is
    # rejected for resource contention, and watch ONE shared window for both signals.
    # A window that stops watching for the "other vault" leak early (while still polling
    # for the target) would miss a leak that is merely delivered late -- EventBridge
    # delivery latency for a native Backup Job State Change event runs up to a few
    # minutes elsewhere in this suite, so a leak arriving after a short negative-only
    # window would go undetected once the check had already moved on to draining the
    # target's message.
    other_job_id = _start_backup_job_with_retry(
        backup, BackupVaultName=other_vault_name, ResourceArn=other_table_arn, IamRoleArn=backup_role_arn
    )["BackupJobId"]
    target_job_id = _start_backup_job_with_retry(
        backup, BackupVaultName=target_vault_name, ResourceArn=target_table_arn, IamRoleArn=backup_role_arn
    )["BackupJobId"]

    delivered, leaked = _poll_sqs_for_target_and_leak(
        sqs, queue_url, target_job_id, other_job_id, timeout_s=220.0
    )
    assert leaked is None, f"event for a different vault ARN must not be delivered, got {leaked}"
    assert delivered is not None, "event for the exact target vault ARN must be delivered"
    body = json.loads(delivered["Body"])
    assert body["detail"]["backupJobId"] == target_job_id, (
        f"expected delivered event's backupJobId to be the target job {target_job_id}, got {body['detail'].get('backupJobId')}"
    )
    assert body["detail"]["backupVaultArn"] == target_vault_arn, (
        f"expected delivered event's backupVaultArn to be {target_vault_arn}, got {body['detail'].get('backupVaultArn')}"
    )


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


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-beh-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name)
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


def _start_backup_job_with_retry(backup, retries: int = 6, delay: float = 10.0, **kwargs):
    """StartBackupJob can reject with an IAM-propagation error immediately after the
    service role's policy attachment, since IAM is eventually consistent. Retry on that
    transient rejection instead of sleeping unconditionally before every call."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(retries):
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay)
    raise last_exc


def _poll_sqs_for_target_and_leak(
    sqs, queue_url: str, target_job_id: str, other_job_id: str, timeout_s: float = 260.0
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Watch one shared window for both signals: the target job's delivered event, and a
    leaked event for the other job. Keeps watching for a leak for the full window even
    after the target event has arrived, so a late leak is not missed just because the
    check had already moved on."""
    deadline = time.monotonic() + timeout_s
    target_msg: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            job_id = body.get("detail", {}).get("backupJobId")
            if job_id == other_job_id:
                return target_msg, m
            if job_id == target_job_id and target_msg is None:
                target_msg = m
    return target_msg, None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

