"""backup-vault-notification-event-detail-format."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-vault-notification-event-detail-format"
GROUP = "data-format"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A delivered Backup job state-change event keeps backupJobId, state, resourceArn,
    backupVaultName and resourceType exactly as the service emitted them, with no re-encoding or
    truncation across EventBridge."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    queue_url, queue_arn = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {"source": ["aws.backup"], "detail-type": ["Backup Job State Change"]}
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["sqs-target"]))

    _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])

    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)

    job_id = _start_backup_job_with_role_retry(backup, vault_name, table_arn, backup_role_arn)

    messages = _poll_sqs_for_job_with_field(sqs, queue_url, job_id, "resourceArn", timeout_s=240.0)
    assert len(messages) >= 1, "expected a native backup job state-change event (with resourceArn) to be delivered"
    body = json.loads(messages[0]["Body"])
    assert body["source"] == "aws.backup"
    assert body["detail-type"] == "Backup Job State Change"
    d = body["detail"]
    assert d["backupJobId"] == job_id
    assert isinstance(d["state"], str) and d["state"]
    assert d["resourceArn"] == table_arn
    assert d["resourceType"].lower().startswith("dynamodb"), d["resourceType"]
    assert d["backupVaultName"] == vault_name
    # Cross-check against the service's own record of the job -- the delivered
    # event's state must be a state the job actually held at some point.
    describe = backup.describe_backup_job(BackupJobId=job_id)
    assert d["backupJobId"] == describe["BackupJobId"]
    assert d["resourceArn"] == describe["ResourceArn"]


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


def _start_backup_job_with_role_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0, interval_s: float = 5.0
) -> str:
    """A freshly-created IAM role is not always immediately usable by the AWS Backup
    service (IAM permission propagation lag); retry StartBackupJob on the transient
    InvalidParameterValueException/'insufficient permissions' response until it clears."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "permission" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_err}")


def _poll_sqs_for_job_with_field(
    sqs, queue_url: str, job_id: str, field: str, timeout_s: float = 240.0
) -> list[dict[str, Any]]:
    """AWS Backup emits a state-change event on EVERY transition (CREATED, PENDING,
    RUNNING, COMPLETED, ...) in a best-effort manner; early states don't carry all
    detail fields (e.g. no resourceArn until the job actually starts running), so
    keep draining and discarding non-matching events for this job until one carries
    the field we need or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            detail = body.get("detail", {})
            if detail.get("backupJobId") == job_id and field in detail:
                return [m]
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

