"""backup-vault-notifications-eventbridge-rule-scoped-by-detail-type."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-vault-notifications-eventbridge-rule-scoped-by-detail-type"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule scoped to one vault's ARN delivers the Backup Job State Change event of a real job in
    that vault and not the event of a real job in another vault, held for a window derived from
    the measured delivery latency."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    table_name, table_arn = _create_table(ctx)
    role_arn = _create_backup_service_role(ctx)
    vault_a_name, vault_a_arn = _create_backup_vault(ctx)
    vault_b_name, vault_b_arn = _create_backup_vault(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"backupVaultArn": [vault_a_arn]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, Force=True))
    queue = _create_events_queue(ctx, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"], Force=True))

    # Positive control first: a REAL backup job into the scoped vault, on this exact
    # rule+target wiring. Measures this run's own delivery latency L.
    positive_start = time.monotonic()
    matching_job_id = _start_backup_job_with_retry(backup, vault_a_name, table_arn, role_arn)["BackupJobId"]
    matched = _wait_for_event_matching(
        sqs, queue["url"], lambda evt: _job_id_in(evt, matching_job_id), timeout_s=120.0
    )
    latency_s = time.monotonic() - positive_start
    assert matched["detail"]["backupVaultArn"] == vault_a_arn, (
        f"expected the delivered event's backupVaultArn to be {vault_a_arn}, "
        f"got {matched['detail'].get('backupVaultArn')}"
    )

    # Negative: an identically-shaped Backup Job State Change event, differing only in
    # backupVaultArn, held for >= 3x the measured positive latency -- isolating the rule's
    # content-based filter rather than "this wiring never delivers anything".
    other_job_id = _start_backup_job_with_retry(backup, vault_b_name, table_arn, role_arn)["BackupJobId"]
    window_s = min(max(15.0, latency_s * 3), 90.0)
    _assert_no_message_matching(sqs, queue["url"], lambda evt: _job_id_in(evt, other_job_id), duration_s=window_s)


def _job_id_in(evt: dict[str, Any], marker: str) -> bool:
    return evt.get("detail", {}).get("backupJobId") == marker


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_backup_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bkuprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    iam.delete_role(RoleName=role_name)


def _start_backup_job_with_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0
) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )
        except ClientError as err:
            last_err = err
            time.sleep(5.0)
    raise AssertionError(f"StartBackupJob never succeeded (likely IAM role propagation): {last_err}")


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-vault-")
    resp = backup.create_backup_vault(
        BackupVaultName=vault_name, BackupVaultTags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _cleanup_vault(backup, vault_name))
    return vault_name, resp["BackupVaultArn"]


def _cleanup_vault(backup, vault_name: str) -> None:
    # A vault with a job still running refuses deletion, so let the jobs settle first.
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline and any(
        backup.list_backup_jobs(ByBackupVaultName=vault_name, ByState=state).get("BackupJobs")
        for state in ("CREATED", "PENDING", "RUNNING")
    ):
        time.sleep(10.0)
    for rp in backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get(
        "RecoveryPoints", []
    ):
        try:
            backup.delete_recovery_point(
                BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    # Recovery-point deletion is asynchronous; the vault refuses deletion until it lands.
    deadline = time.monotonic() + 300.0
    while True:
        try:
            backup.delete_backup_vault(BackupVaultName=vault_name)
            return
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code != "InvalidRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(10.0)


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-evtq-"), tags={"sim2real-check": CHECK}
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


def _wait_for_event_matching(sqs, queue_url: str, match_fn, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s")


def _assert_no_message_matching(sqs, queue_url: str, match_fn, duration_s: float) -> None:
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                raise AssertionError(f"event scoped to a different vault ARN was unexpectedly delivered: {body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
