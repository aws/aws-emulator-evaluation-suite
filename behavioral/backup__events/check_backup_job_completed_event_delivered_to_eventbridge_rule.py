"""backup-job-completed-event-delivered-to-eventbridge-rule."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-job-completed-event-delivered-to-eventbridge-rule"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real AWS Backup on-demand backup job reaching COMPLETED is delivered via a
    default-bus EventBridge rule to an SQS target, carrying the same job id."""
    table_name, table_arn = _create_dynamodb_table(ctx)
    vault_name, _vault_arn = _create_backup_vault(ctx)
    _role_name, role_arn = _create_backup_service_role(ctx)
    queue_url, queue_arn = _create_sqs_target(ctx)
    _rule_name, rule_arn = _create_rule_with_sqs_target(
        ctx,
        pattern={"source": ["aws.backup"], "detail-type": ["Backup Job State Change"]},
        queue_url=queue_url,
        queue_arn=queue_arn,
    )

    backup = ctx.client("backup")

    def _start():
        return backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn=table_arn,
            IamRoleArn=role_arn,
            IdempotencyToken=str(uuid.uuid4()),
        )

    resp = _retry_until_success(_start, retry_codes={"InvalidParameterValueException"})
    job_id = resp["BackupJobId"]

    final = _wait_backup_job_state(ctx, job_id, {"COMPLETED", "FAILED", "ABORTED", "EXPIRED"})
    assert final["State"] == "COMPLETED", f"backup job ended in {final['State']}: {final.get('StatusMessage')}"

    message = _wait_for_message(
        ctx,
        queue_url,
        predicate=lambda body: (
            body.get("detail", {}).get("backupJobId") == job_id
            and body.get("detail", {}).get("state") == "COMPLETED"
        ),
        timeout_s=300.0,
    )
    assert message is not None, (
        "no EventBridge-delivered COMPLETED event observed for the backup job "
        "(AWS Backup emits one state-change event per lifecycle transition, e.g. PENDING, "
        "RUNNING, COMPLETED, all sharing the same backupJobId, so the terminal one must be "
        "selected by state, not merely by job id)"
    )
    assert message["source"] == "aws.backup", f"expected source aws.backup, got {message['source']!r}"
    assert message["detail-type"] == "Backup Job State Change", (
        f"expected detail-type 'Backup Job State Change', got {message['detail-type']!r}"
    )
    assert message["detail"]["state"] == "COMPLETED", f"expected detail.state COMPLETED, got {message['detail']['state']!r}"
    assert message["detail"]["backupVaultName"] == vault_name, (
        f"expected detail.backupVaultName {vault_name!r}, got {message['detail'].get('backupVaultName')!r}"
    )


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


_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_TAGS_MAP = {"sim2real:managed": "true"}


def _create_dynamodb_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-vault-")
    backup.create_backup_vault(BackupVaultName=name, BackupVaultTags=_TAGS_MAP)
    ctx.on_cleanup(lambda: _delete_vault_best_effort(backup, name))
    vault = backup.describe_backup_vault(BackupVaultName=name)
    return name, vault["BackupVaultArn"]


def _delete_vault_best_effort(backup, vault_name: str) -> None:
    # A vault refuses DeleteBackupVault while it still holds a recovery point, and
    # DeleteRecoveryPoint is itself async -- so this is best-effort, matching the
    # other try/except ClientError teardowns in this file. A vault this fails to
    # clear is cheap (no ongoing charge) and stays tagged for a later sweep.
    try:
        points = backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get("RecoveryPoints", [])
        for point in points:
            backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=point["RecoveryPointArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        backup.delete_backup_vault(BackupVaultName=vault_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_backup_service_role(ctx, extra_managed_policies: list[str] | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV)
    role_arn = role["Role"]["Arn"]
    policies = ["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"]
    if extra_managed_policies:
        policies.extend(extra_managed_policies)
    for policy_arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in policies:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _create_sqs_target(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-evtq-")
    url = sqs.create_queue(QueueName=name, tags=_TAGS_MAP)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_rule_with_sqs_target(ctx, pattern: dict, queue_url: str, queue_arn: str) -> tuple[str, str]:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_name = ctx.unique_name("sim2real-rule-")
    rule = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED", Tags=_TAGS_KV)
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
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
    target_id = "target-1"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))
    return rule_name, rule_arn


def _wait_backup_job_state(ctx, job_id: str, target_states: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0) -> dict:
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = backup.describe_backup_job(BackupJobId=job_id)
        if last["State"] in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"backup job {job_id} did not reach {target_states} within {timeout_s}s "
        f"(last state={last.get('State')})"
    )


def _wait_for_message(ctx, queue_url: str, predicate: Callable[[dict], bool], timeout_s: float = 300.0) -> dict | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except ValueError:
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body is not None and predicate(body):
                return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
