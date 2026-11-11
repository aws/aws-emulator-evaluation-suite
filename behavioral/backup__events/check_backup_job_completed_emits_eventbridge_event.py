"""backup-job-completed-emits-eventbridge-event."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "backup-job-completed-emits-eventbridge-event"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real DynamoDB on-demand backup job that reaches COMPLETED emits a genuine
    'Backup Job State Change' EventBridge event (source aws.backup) which is delivered to a
    subscribed SQS queue carrying the job's true id/state/resourceArn."""
    # One teardown deadline per run, shared by every vault teardown.
    teardown_deadline: dict = {}
    events = ctx.client("events")
    backup = ctx.client("backup")

    role_arn = _create_backup_role(ctx)
    table_arn = _create_backup_table(ctx)
    vault_name, _vault_arn = _create_backup_vault(ctx, teardown_deadline)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"backupVaultName": [vault_name], "state": ["COMPLETED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    job_id, final_job = _run_backup_job_to_completion(backup, vault_name, table_arn, role_arn)

    event = _wait_for_event_matching(
        ctx,
        queue["url"],
        lambda evt: evt.get("detail", {}).get("backupJobId") == job_id,
        timeout_s=300,
        interval_s=5.0,
    )
    assert event["detail-type"] == "Backup Job State Change", (
        f"expected detail-type 'Backup Job State Change', got {event['detail-type']!r}"
    )
    assert event["source"] == "aws.backup", f"expected source 'aws.backup', got {event['source']!r}"
    detail = event["detail"]
    assert detail["backupJobId"] == job_id, (
        f"expected event backupJobId {job_id!r}, got {detail['backupJobId']!r}"
    )
    assert detail["state"] == "COMPLETED", f"expected event state 'COMPLETED', got {detail['state']!r}"
    assert detail["resourceArn"] == table_arn, (
        f"expected event resourceArn {table_arn!r}, got {detail['resourceArn']!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in [
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    ]:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
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


# Inside the 900 s cleanup budget of this suite, one deadline shared by every vault teardown.
_VAULT_TEARDOWN_S = 780.0
_ACTIVE_JOB_STATES = ("CREATED", "PENDING", "RUNNING", "ABORTING")


def _empty_and_delete_vault(backup, vault_name, teardown_deadline):
    """Stop the vault's unfinished backup jobs and delete its recovery points, then delete the vault.
    AWS refuses the vault delete while it holds either and deletes recovery points asynchronously,
    so the vault is re-read every 2 s to the cleanup deadline. A vault that is already gone is done."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _VAULT_TEARDOWN_S)
    while True:
        busy = False
        for job in backup.list_backup_jobs(ByBackupVaultName=vault_name)["BackupJobs"]:
            if job["State"] in _ACTIVE_JOB_STATES:
                busy = True
                if job["State"] != "ABORTING":
                    _tolerate_race(lambda j=job: backup.stop_backup_job(BackupJobId=j["BackupJobId"]))
        try:
            points = backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name)["RecoveryPoints"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        for point in points:
            if point.get("Status") != "DELETING":
                _tolerate_race(
                    lambda p=point: backup.delete_recovery_point(
                        BackupVaultName=vault_name, RecoveryPointArn=p["RecoveryPointArn"]
                    )
                )
        if not busy and not points:
            try:
                backup.delete_backup_vault(BackupVaultName=vault_name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "InvalidRequestException":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"backup vault {vault_name} still holds backup jobs or recovery points after "
                f"{_VAULT_TEARDOWN_S}s"
            )
        time.sleep(2)


def _tolerate_race(fn):
    """Run a stop or delete that can lose a race with the job or recovery point finishing on its
    own; the next pass re-reads the vault, and any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "InvalidRequestException",
            "InvalidResourceStateException",
        ):
            raise


def _create_backup_vault(ctx, teardown_deadline) -> tuple[str, str]:
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-vault-")
    resp = backup.create_backup_vault(
        BackupVaultName=vault_name, BackupVaultTags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_vault(backup, vault_name, teardown_deadline))
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


def _run_backup_job_to_completion(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 300.0
) -> tuple[str, dict]:
    """A DynamoDB table freshly created needs a brief AWS-side warm-up before AWS Backup
    can back it up: StartBackupJob succeeds and returns a job id, but the job then goes
    FAILED with StatusMessage 'Backups are being enabled for the table ... Please retry
    later.' Retry the whole start+wait cycle while that specific, named condition holds;
    any other terminal state fails immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        job_id = _start_backup_job_with_retry(backup, vault_name, resource_arn, role_arn)
        final_job = _poll_until(
            lambda: backup.describe_backup_job(BackupJobId=job_id),
            lambda j: j["State"] in ("COMPLETED", "FAILED", "ABORTED"),
            timeout_s=1200,
            interval_s=5.0,
            description=f"backup job {job_id} terminal state",
        )
        if final_job["State"] == "COMPLETED":
            return job_id, final_job
        message = final_job.get("StatusMessage") or ""
        if (
            final_job["State"] == "FAILED"
            and "being enabled" in message
            and time.monotonic() < deadline
        ):
            time.sleep(2.0)
            continue
        raise AssertionError(
            f"expected backup job {job_id} to reach COMPLETED, got {final_job['State']}: {message!r}"
        )


def _wait_for_event_matching(
    ctx, queue_url: str, match_fn, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
            seen.append(body)
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(
        f"no matching event arrived on {queue_url} within {timeout_s}s; "
        f"saw {len(seen)} non-matching message(s): {seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
