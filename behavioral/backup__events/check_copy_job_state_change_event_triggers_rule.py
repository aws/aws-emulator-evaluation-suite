"""copy-job-state-change-event-triggers-rule."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-job-state-change-event-triggers-rule"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real AWS Backup CopyJob state change is captured by an EventBridge rule
    that filters only on source=aws.backup and delivered to an SQS target."""
    table_name, table_arn = _create_dynamodb_table(ctx)
    src_vault_name, _src_vault_arn = _create_backup_vault(ctx)
    _dst_vault_name, dst_vault_arn = _create_backup_vault(ctx)
    _role_name, role_arn = _create_backup_service_role(ctx)

    backup = ctx.client("backup")

    def _start_backup():
        return backup.start_backup_job(
            BackupVaultName=src_vault_name,
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
        ctx, pattern={"source": ["aws.backup"]}, queue_url=queue_url, queue_arn=queue_arn
    )

    def _start_copy():
        return backup.start_copy_job(
            RecoveryPointArn=recovery_point_arn,
            SourceBackupVaultName=src_vault_name,
            DestinationBackupVaultArn=dst_vault_arn,
            IamRoleArn=role_arn,
            IdempotencyToken=str(uuid.uuid4()),
        )

    copy_resp = _retry_until_success(_start_copy, retry_codes={"InvalidParameterValueException"})
    copy_job_id = copy_resp["CopyJobId"]

    final_copy = _wait_copy_job_state(ctx, copy_job_id, {"COMPLETED", "FAILED"})
    assert final_copy["State"] == "COMPLETED", f"copy job did not complete: {final_copy}"

    message = _wait_for_message(
        ctx,
        queue_url,
        predicate=lambda body: body.get("detail", {}).get("copyJobId") == copy_job_id,
        timeout_s=300.0,
    )
    assert message is not None, "no EventBridge-delivered copy-job event observed under a source-only pattern"
    assert message["source"] == "aws.backup", f"expected source=aws.backup, got {message['source']!r}"
    assert message["detail-type"] == "Copy Job State Change", (
        f"expected detail-type='Copy Job State Change', got {message['detail-type']!r}"
    )
    assert message["detail"]["state"] == "COMPLETED", f"expected detail.state=COMPLETED, got {message['detail']['state']!r}"
    assert message["detail"]["destinationBackupVaultArn"] == dst_vault_arn, (
        f"expected detail.destinationBackupVaultArn={dst_vault_arn!r}, got "
        f"{message['detail']['destinationBackupVaultArn']!r}"
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


def _create_backup_service_role(ctx) -> tuple[str, str]:
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
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
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


def _wait_copy_job_state(ctx, job_id: str, target_states: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0) -> dict:
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = backup.describe_copy_job(CopyJobId=job_id)["CopyJob"]
        if last["State"] in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"copy job {job_id} did not reach {target_states} within {timeout_s}s "
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
