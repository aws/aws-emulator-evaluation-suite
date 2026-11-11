"""restore-job-completed-event-triggers-rule."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-job-completed-event-triggers-rule"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real AWS Backup RestoreJob reaching COMPLETED is captured by an EventBridge
    rule filtering on 'Restore Job State Change' and delivered to an SQS target."""
    table_name, table_arn = _create_dynamodb_table(ctx)
    vault_name, _vault_arn = _create_backup_vault(ctx)
    _role_name, role_arn = _create_backup_service_role(
        ctx, extra_managed_policies=["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"]
    )

    backup = ctx.client("backup")

    def _start_backup():
        return backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn=table_arn,
            IamRoleArn=role_arn,
            IdempotencyToken=str(uuid.uuid4()),
        )

    backup_resp = _retry_until_success(_start_backup, retry_codes={"InvalidParameterValueException"})
    backup_job = _wait_backup_job_state(ctx, backup_resp["BackupJobId"], {"COMPLETED", "FAILED", "ABORTED", "EXPIRED"})
    assert backup_job["State"] == "COMPLETED", f"prerequisite backup job did not complete: {backup_job}"
    recovery_point_arn = backup_job["RecoveryPointArn"]

    queue_url, queue_arn = _create_sqs_target(ctx)
    _rule_name, rule_arn = _create_rule_with_sqs_target(
        ctx,
        pattern={"source": ["aws.backup"], "detail-type": ["Restore Job State Change"]},
        queue_url=queue_url,
        queue_arn=queue_arn,
    )

    restored_table_name = ctx.unique_name("sim2real-restored-tbl-")
    ddb = ctx.client("dynamodb")
    ctx.on_cleanup(lambda: _best_effort_delete_table(ddb, restored_table_name))

    def _start_restore():
        return backup.start_restore_job(
            RecoveryPointArn=recovery_point_arn,
            Metadata={"TargetTableName": restored_table_name},
            IamRoleArn=role_arn,
            ResourceType="DynamoDB",
        )

    restore_resp = _retry_until_success(_start_restore, retry_codes={"InvalidParameterValueException"})
    restore_job_id = restore_resp["RestoreJobId"]

    final_restore = _wait_restore_job_status(ctx, restore_job_id, {"COMPLETED", "FAILED", "ABORTED"})
    assert final_restore["Status"] == "COMPLETED", f"restore job did not complete: {final_restore}"

    # AWS Backup emits a "Restore Job State Change" event at each lifecycle transition
    # (e.g. RUNNING before COMPLETED), not just the terminal one, so the wait must select
    # for a terminal status rather than the first event carrying this restoreJobId.
    message = _wait_for_message(
        ctx,
        queue_url,
        predicate=lambda body: (
            body.get("detail", {}).get("restoreJobId") == restore_job_id
            and body.get("detail", {}).get("status") in {"COMPLETED", "FAILED", "ABORTED"}
        ),
        timeout_s=300.0,
    )
    assert message is not None, "no EventBridge-delivered restore-job event observed"
    assert message["source"] == "aws.backup", f"expected source 'aws.backup', got {message['source']!r}"
    assert message["detail-type"] == "Restore Job State Change", (
        f"expected detail-type 'Restore Job State Change', got {message['detail-type']!r}"
    )
    assert message["detail"]["status"] == "COMPLETED", (
        f"expected detail.status 'COMPLETED', got {message['detail']['status']!r}"
    )


def _best_effort_delete_table(ddb, name: str) -> None:
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


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


def _create_dynamodb_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-vault-")
    backup.create_backup_vault(BackupVaultName=name)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=name))
    vault = backup.describe_backup_vault(BackupVaultName=name)
    return name, vault["BackupVaultArn"]


def _create_backup_service_role(ctx, extra_managed_policies: list[str] | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_rule_with_sqs_target(ctx, pattern: dict, queue_url: str, queue_arn: str) -> tuple[str, str]:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_name = ctx.unique_name("sim2real-rule-")
    rule = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
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


def _wait_restore_job_status(ctx, job_id: str, target_statuses: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0) -> dict:
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = backup.describe_restore_job(RestoreJobId=job_id)
        if last["Status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"restore job {job_id} did not reach {target_statuses} within {timeout_s}s "
        f"(last status={last.get('Status')})"
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
