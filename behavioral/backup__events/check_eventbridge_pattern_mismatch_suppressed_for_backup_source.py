"""eventbridge-pattern-mismatch-suppressed-for-backup-source."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-pattern-mismatch-suppressed-for-backup-source"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule requiring source aws.backup does not fire for an event with another source and the
    same detail-type, while a real aws.backup job event on the same rule is delivered."""
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

    # Mismatched source, identical detail-type and detail shape. Customer-submitted
    # sources can never forge "aws.backup", so this is the interesting negative case.
    mismatched_job_id = ctx.unique_name("mismatched-")
    detail = {"backupJobId": mismatched_job_id, "state": "COMPLETED"}
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.other-service",
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps(detail),
            }
        ]
    )
    leftover = _poll_sqs(sqs, queue_url, min_count=1, timeout_s=20.0)
    assert leftover == [], f"mismatched-source event must not be delivered, got {leftover}"

    # Positive control: same rule, a REAL aws.backup job's native event, must
    # deliver (customer PutEvents cannot forge "aws.backup", so we drive an
    # actual backup job to prove the rule/target wiring itself is sound).
    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)
    def _start_backup_job():
        return backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn=table_arn,
            IamRoleArn=backup_role_arn,
            IdempotencyToken=str(uuid.uuid4()),
        )

    # The freshly-attached role policy is not always assumable by backup.amazonaws.com
    # the instant attach_role_policy returns; IAM propagation is eventually consistent
    # so retry the start call itself, bounded, instead of sleeping a fixed time.
    matching_job_id = _retry_until_success(
        _start_backup_job, retry_codes={"InvalidParameterValueException"}
    )["BackupJobId"]

    delivered = _poll_sqs_for_job(sqs, queue_url, matching_job_id, timeout_s=180.0)
    assert len(delivered) >= 1, "matching aws.backup event must still be delivered by the same rule"
    body = json.loads(delivered[0]["Body"])
    assert body["detail"]["backupJobId"] == matching_job_id, (
        f"delivered event backupJobId {body['detail'].get('backupJobId')!r} != started job {matching_job_id!r}"
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


def _retry_until_success(fn, retry_codes: set[str], timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
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


def _poll_sqs(sqs, queue_url: str, min_count: int = 1, timeout_s: float = 30.0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _poll_sqs_for_job(sqs, queue_url: str, job_id: str, timeout_s: float = 180.0) -> list[dict[str, Any]]:
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

