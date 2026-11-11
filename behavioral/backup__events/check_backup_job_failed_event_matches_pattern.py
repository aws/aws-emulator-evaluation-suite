"""backup-job-failed-event-matches-pattern."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-job-failed-event-matches-pattern"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule pattern scoped to detail.state=FAILED delivers a real FAILED BackupJob
    state-change event, and none of that same job's other (non-FAILED) transitions."""
    table_name, table_arn = _create_dynamodb_table(ctx)
    vault_name, _vault_arn = _create_backup_vault(ctx)
    # Deliberately a role with NO permissions policy attached (trust-only) so the
    # backup service cannot call dynamodb:CreateBackup and the job fails.
    _role_name, powerless_role_arn = _create_powerless_backup_role(ctx)
    queue_url, queue_arn = _create_sqs_target(ctx)
    _rule_name, rule_arn = _create_rule_with_sqs_target(
        ctx,
        pattern={
            "source": ["aws.backup"],
            "detail-type": ["Backup Job State Change"],
            "detail": {"state": ["FAILED"]},
        },
        queue_url=queue_url,
        queue_arn=queue_arn,
    )

    backup = ctx.client("backup")

    def _start():
        return backup.start_backup_job(
            BackupVaultName=vault_name,
            ResourceArn=table_arn,
            IamRoleArn=powerless_role_arn,
            IdempotencyToken=str(uuid.uuid4()),
        )

    resp = _retry_until_success(_start, retry_codes={"InvalidParameterValueException"})
    job_id = resp["BackupJobId"]

    final = _wait_backup_job_state(ctx, job_id, {"COMPLETED", "FAILED", "ABORTED", "EXPIRED"})
    assert final["State"] == "FAILED", f"expected the permission-less job to FAIL, got {final['State']}"

    all_messages = _collect_messages(ctx, queue_url, timeout_s=180.0)
    job_messages = [m for m in all_messages if m.get("detail", {}).get("backupJobId") == job_id]
    assert job_messages, "the FAILED-state-only rule never delivered the failed job's event"
    non_failed = [m for m in job_messages if m["detail"]["state"] != "FAILED"]
    assert not non_failed, f"rule delivered non-FAILED state events despite detail.state=FAILED pattern: {non_failed}"
    assert all(m["detail"]["state"] == "FAILED" for m in job_messages), f"expected every delivered detail.state to be FAILED, got {[m['detail']['state'] for m in job_messages]}"
    assert all(m["detail-type"] == "Backup Job State Change" for m in job_messages), f"expected every delivered detail-type to be 'Backup Job State Change', got {[m['detail-type'] for m in job_messages]}"
    assert all(m["source"] == "aws.backup" for m in job_messages), f"expected every delivered source to be 'aws.backup', got {[m['source'] for m in job_messages]}"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-vault-")
    backup.create_backup_vault(BackupVaultName=name, BackupVaultTags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=name))
    vault = backup.describe_backup_vault(BackupVaultName=name)
    return name, vault["BackupVaultArn"]


def _create_powerless_backup_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role["Role"]["Arn"]


def _create_sqs_target(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-evtq-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_rule_with_sqs_target(ctx, pattern: dict, queue_url: str, queue_arn: str) -> tuple[str, str]:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_name = ctx.unique_name("sim2real-rule-")
    rule = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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


def _wait_backup_job_state(ctx, job_id: str, target_states: set[str], timeout_s: float = 1800.0, interval_s: float = 15.0) -> dict:
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


def _collect_messages(ctx, queue_url: str, timeout_s: float) -> list[dict]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    out: list[dict] = []
    while time.monotonic() < deadline:
        remaining = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except ValueError:
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body is not None:
                out.append(body)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
