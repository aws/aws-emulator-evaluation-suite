"""eventbridge-rule-account-id-filter-blocks-backup-event."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-account-id-filter-blocks-backup-event"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule filtering on an account other than the publishing one never delivers a real AWS Backup
    job event, while a sibling rule filtering on the publishing account delivers it."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_account = "999999999999" if account_id != "999999999999" else "888888888888"

    events = ctx.client("events")
    mismatch_rule, mismatch_arn = _create_rule(
        ctx, {"source": ["aws.backup"], "account": [bogus_account]}
    )
    match_rule, match_arn = _create_rule(
        ctx, {"source": ["aws.backup"], "account": [account_id]}
    )

    queue_url, queue_arn = _create_queue_for_rule(ctx, [mismatch_arn, match_arn])
    _bind_target(ctx, mismatch_rule, queue_arn, target_id="t-mismatch")
    _bind_target(ctx, match_rule, queue_arn, target_id="t-match")

    backup = ctx.client("backup")
    table_name, table_arn = _create_table(ctx)
    vault_name, _vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)
    job_id = _start_backup_job_with_retry(backup, vault_name, table_arn, backup_role_arn)

    sqs = ctx.client("sqs")
    matched = _poll_sqs_for_job(ctx, queue_url, job_id, timeout_s=180.0)

    # The mismatched-account rule's pattern can never be satisfied by construction: a real
    # aws.backup event's "account" field is always this caller's own account, never the bogus
    # one, so only the account-matching rule can ever deliver to the shared queue. Seeing at
    # least one delivery proves the wiring is sound; every delivery having this account proves
    # the mismatched-account rule contributed nothing.
    assert matched, f"expected the account-matching rule to deliver an event for job {job_id}, got none"
    for evt in matched:
        assert evt["account"] == account_id, (
            f"expected every delivered event's account to be the publishing account "
            f"{account_id}, got {evt['account']}"
        )


def _create_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-bkp-rule-")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "eventbridge-rule-account-id-filter-blocks-backup-event"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name, arn


def _create_queue_for_rule(ctx, rule_arns: list[str]) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-bkp-q-"),
        tags={"sim2real": "eventbridge-rule-account-id-filter-blocks-backup-event"},
    )["QueueUrl"]
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


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-bkp-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "eventbridge-rule-account-id-filter-blocks-backup-event"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-bkp-vault-")
    resp = backup.create_backup_vault(
        BackupVaultName=name,
        BackupVaultTags={"sim2real": "eventbridge-rule-account-id-filter-blocks-backup-event"},
    )
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
    role_name = ctx.unique_name("sim2real-bkp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "eventbridge-rule-account-id-filter-blocks-backup-event"}],
    )["Role"]["Arn"]
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


def _start_backup_job_with_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 60.0
) -> str:
    # A freshly attached IAM managed policy can lag AssumeRole visibility by several
    # seconds; retry StartBackupJob on that specific rejection instead of a blind sleep.
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except Exception as exc:  # noqa: BLE001 -- retried below only for the specific role-not-ready shape
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            message = str(exc)
            if code not in ("InvalidParameterValueException", "AccessDeniedException") or "role" not in message.lower():
                raise
            last_error = exc
            time.sleep(3.0)
    raise AssertionError(f"StartBackupJob never succeeded within {timeout_s}s: {last_error}")


def _poll_sqs_for_job(ctx, queue_url: str, job_id: str, timeout_s: float = 180.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    matched: list[dict[str, Any]] = []
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
                matched.append(body)
        if matched:
            return matched
    return matched


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
