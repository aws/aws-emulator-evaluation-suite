"""copy-job-state-change-event-pattern-match."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "copy-job-state-change-event-pattern-match"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule on detail-type 'Copy Job State Change' receives the event of a real cross-vault copy
    job, while a sibling rule on 'Backup Job State Change' receives nothing for the copy."""
    events = ctx.client("events")
    backup = ctx.client("backup")

    role_arn = _create_backup_role(ctx)
    table_arn = _create_backup_table(ctx)
    src_vault_name, src_vault_arn = _create_backup_vault(ctx)
    dst_vault_name, dst_vault_arn = _create_backup_vault(ctx)

    # Rule #1: only matches Copy Job State Change events for our source vault.
    copy_rule_name = ctx.unique_name("sim2real-rule-copy-")
    copy_pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Copy Job State Change"],
        "detail": {"sourceBackupVaultArn": [src_vault_arn]},
    }
    copy_rule_arn = events.put_rule(
        Name=copy_rule_name, EventPattern=json.dumps(copy_pattern), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=copy_rule_name))
    copy_queue = _create_events_queue(ctx, copy_rule_arn)
    events.put_targets(Rule=copy_rule_name, Targets=[{"Id": "t1", "Arn": copy_queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=copy_rule_name, Ids=["t1"]))

    # Rule #2: only matches Backup Job State Change events for the same vault -- created fresh
    # (empty) right before the copy job starts, so any message on it proves cross-detail-type leakage.
    backup_rule_name = ctx.unique_name("sim2real-rule-backup-")
    backup_pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"backupVaultName": [src_vault_name]},
    }
    backup_rule_arn = events.put_rule(
        Name=backup_rule_name, EventPattern=json.dumps(backup_pattern), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=backup_rule_name))
    backup_queue = _create_events_queue(ctx, backup_rule_arn)
    events.put_targets(Rule=backup_rule_name, Targets=[{"Id": "t1", "Arn": backup_queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=backup_rule_name, Ids=["t1"]))

    backup_job_id = _start_backup_job_with_retry(backup, src_vault_name, table_arn, role_arn)
    backup_final = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=backup_job_id)["State"],
        lambda s: s in ("COMPLETED", "FAILED", "ABORTED"),
        timeout_s=1200,
        interval_s=5.0,
        description=f"backup job {backup_job_id} terminal state",
    )
    _backup_job_desc = backup.describe_backup_job(BackupJobId=backup_job_id)
    assert backup_final == "COMPLETED", (
        f"backup job {backup_job_id} ended in {backup_final}, expected COMPLETED: "
        f"{_backup_job_desc.get('StatusMessage')!r}"
    )
    recovery_point_arn = backup.describe_backup_job(BackupJobId=backup_job_id)["RecoveryPointArn"]

    # Positive control: prove the backup-job rule/queue wiring actually delivers a matching
    # event at all -- the rule existed before the backup job started, so the job's own
    # COMPLETED "Backup Job State Change" event must land here. Without this, a rule that
    # never delivers anything (a broken pattern, a missing target permission) would make the
    # copy-job leakage check below pass for the wrong reason: nothing arrives either way.
    # Real AWS Backup emits one "Backup Job State Change" event per intermediate transition
    # (e.g. RUNNING), not just the terminal one, so the match must pin the COMPLETED state
    # itself -- matching on backupJobId alone can return an earlier, non-terminal event.
    backup_job_event = _wait_for_event_matching(
        ctx,
        backup_queue["url"],
        lambda evt: evt.get("detail", {}).get("backupJobId") == backup_job_id
        and evt.get("detail", {}).get("state") == "COMPLETED",
        timeout_s=300,
        interval_s=5.0,
    )
    assert backup_job_event["detail-type"] == "Backup Job State Change"
    assert backup_job_event["detail"]["state"] == "COMPLETED"

    # Drain (and discard) anything else left on the backup-job queue before the copy job starts.
    _drain_all(ctx, backup_queue["url"])

    copy_job_id = backup.start_copy_job(
        RecoveryPointArn=recovery_point_arn,
        SourceBackupVaultName=src_vault_name,
        DestinationBackupVaultArn=dst_vault_arn,
        IamRoleArn=role_arn,
    )["CopyJobId"]
    copy_final = _poll_until(
        lambda: backup.describe_copy_job(CopyJobId=copy_job_id)["CopyJob"]["State"],
        lambda s: s in ("COMPLETED", "FAILED"),
        timeout_s=1200,
        interval_s=5.0,
        description=f"copy job {copy_job_id} terminal state",
    )
    assert copy_final == "COMPLETED", f"copy job ended in {copy_final}, expected COMPLETED"

    # Same reasoning as the backup-job positive control above: pin the terminal state in the
    # match itself, since an intermediate "Copy Job State Change" event can share the same
    # copyJobId.
    copy_event = _wait_for_event_matching(
        ctx,
        copy_queue["url"],
        lambda evt: evt.get("detail", {}).get("copyJobId") == copy_job_id
        and evt.get("detail", {}).get("state") == "COMPLETED",
        timeout_s=300,
        interval_s=5.0,
    )
    assert copy_event["detail-type"] == "Copy Job State Change"
    assert copy_event["detail"]["state"] == "COMPLETED"

    leaked = _drain_all(ctx, backup_queue["url"])
    assert leaked == [], f"Backup Job State Change rule unexpectedly received copy job traffic: {leaked}"


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
    # A fresh table starts enabling continuous backups (PITR) on its own -- not
    # something this check requested -- and that enablement is asynchronous: a
    # StartBackupJob issued before it finishes fails immediately with "Backups are being
    # enabled for the table ... Please retry later" (a real terminal FAILED, not a timeout, so
    # no amount of patience in the backup-job poll below would recover it). Calling
    # UpdateContinuousBackups while that is already in flight raises
    # ContinuousBackupsUnavailableException rather than being idempotent, so only call it when
    # the table isn't already on its way to ENABLED, then wait for ENABLED either way.
    from botocore.exceptions import ClientError

    def _ensure_pitr_enabling() -> str:
        status = ddb.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"][
            "PointInTimeRecoveryDescription"
        ]["PointInTimeRecoveryStatus"]
        if status == "DISABLED":
            try:
                ddb.update_continuous_backups(
                    TableName=table_name, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True}
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                    raise
        return status

    _poll_until(
        _ensure_pitr_enabling,
        lambda s: s == "ENABLED",
        timeout_s=600,
        interval_s=5.0,
        description="table PointInTimeRecoveryStatus ENABLED",
    )
    return ddb.describe_table(TableName=table_name)["Table"]["TableArn"]


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-vault-")
    resp = backup.create_backup_vault(BackupVaultName=vault_name, BackupVaultTags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))
    return vault_name, resp["BackupVaultArn"]


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evtq-"), tags={"sim2real": CHECK})["QueueUrl"]
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


def _drain_all(ctx, queue_url: str) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    while True:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
