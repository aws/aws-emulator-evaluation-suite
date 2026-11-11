"""backup-job-failed-state-change-event-detail."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "backup-job-failed-state-change-event-detail"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A backup job that fails (IAM role lacking the permissions AWS Backup needs to create
    the recovery point) emits a 'Backup Job State Change' event in state FAILED whose detail
    carries a non-empty statusMessage describing the failure reason."""
    events = ctx.client("events")
    backup = ctx.client("backup")

    role_arn = _create_permissionless_backup_role(ctx)
    table_arn = _create_backup_table(ctx)
    vault_name, _vault_arn = _create_backup_vault(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"backupVaultName": [vault_name], "state": ["FAILED"]},
    }
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    job_id = _start_backup_job_with_retry(backup, vault_name, table_arn, role_arn)

    final_state = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id)["State"],
        lambda s: s in ("COMPLETED", "FAILED", "ABORTED"),
        timeout_s=600,
        interval_s=5.0,
        description=f"backup job {job_id} terminal state",
    )
    assert final_state == "FAILED", f"backup job ended in {final_state}, expected FAILED"

    event = _wait_for_event_matching(
        ctx,
        queue["url"],
        lambda evt: evt.get("detail", {}).get("backupJobId") == job_id,
        timeout_s=120,
        interval_s=5.0,
    )
    detail = event["detail"]
    assert detail["backupJobId"] == job_id, f"expected backupJobId {job_id!r}, got {detail['backupJobId']!r}"
    assert detail["state"] == "FAILED", f"expected detail.state FAILED, got {detail['state']!r}"
    status_message = detail.get("statusMessage")
    assert isinstance(status_message, str) and len(status_message) > 0, (
        f"expected a non-empty statusMessage describing the failure, got {status_message!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_permissionless_backup_role(ctx) -> str:
    """A role AWS Backup can assume (correct trust policy) but with zero permissions attached,
    so StartBackupJob is accepted but the job fails asynchronously with AccessDenied."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-backup-noperm-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_backup_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        BackupVaultName=vault_name, BackupVaultTags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))
    return vault_name, resp["BackupVaultArn"]


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-evtq-"), tags={"sim2real": CHECK}
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


def _start_backup_job_with_retry(backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0) -> str:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
