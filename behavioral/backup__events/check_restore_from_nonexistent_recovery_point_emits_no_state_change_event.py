"""restore-from-nonexistent-recovery-point-emits-no-state-change-event."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-from-nonexistent-recovery-point-emits-no-state-change-event"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartRestoreJob from a nonexistent recovery point is rejected synchronously, creates no
    restore job, and delivers no Restore Job State Change event; a real Backup Job State Change
    event on the same rule and target is the positive control for the delivery path."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    account = ctx.client("sts").get_caller_identity()["Account"]

    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)

    queue_url, queue_arn = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Restore Job State Change", "Backup Job State Change"],
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["sqs-target"]))

    _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])

    # Positive control on the same rule/target/policy: a real backup job's native
    # "Backup Job State Change" event proves the aws.backup -> EventBridge -> SQS
    # pipe is genuinely live, long before a DynamoDB backup job could ever reach
    # COMPLETED.
    backup_job_id = _start_backup_job_with_retry(backup, vault_name, table_arn, backup_role_arn)
    # Runs before the vault teardown: an active job keeps the vault undeletable.
    ctx.on_cleanup(lambda: _stop_if_active(backup, backup_job_id))
    control_event = _wait_for_event_matching(
        sqs,
        queue_url,
        lambda evt: evt.get("detail-type") == "Backup Job State Change"
        and evt.get("detail", {}).get("backupJobId") == backup_job_id,
        timeout_s=180.0,
    )
    assert control_event["detail"]["backupJobId"] == backup_job_id, (
        "positive control: no native 'Backup Job State Change' event observed for the real "
        "backup job -- the rule/target/policy wiring for aws.backup events is not proven live, "
        "so the non-delivery assertion below would be meaningless"
    )

    fake_recovery_point_arn = (
        f"arn:aws:backup:{ctx.region}:{account}:recovery-point:00000000-0000-0000-0000-000000000000"
    )
    restored_table_name = ctx.unique_name("sim2real-beh-restored-")
    error_code = None
    error_message = None
    try:
        backup.start_restore_job(
            RecoveryPointArn=fake_recovery_point_arn,
            Metadata={"TargetTableName": restored_table_name},
            IamRoleArn=backup_role_arn,
            ResourceType="DynamoDB",
        )
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: _delete_table_if_exists(ctx, restored_table_name))
    assert (error_code, error_message) == (
        "InvalidParameterValueException", "Cannot find recovery point"
    ), (
        f"expected StartRestoreJob against a nonexistent recovery point to be rejected synchronously "
        f"with InvalidParameterValueException 'Cannot find recovery point', got "
        f"{error_code!r} {error_message!r}"
    )

    # Nothing tagged as a Restore Job State Change should ever land on the queue for
    # a restore job that was never created. The real backup job above (and any
    # further "Backup Job State Change" events it emits as it progresses) shares
    # this same queue and is expected traffic -- only the specific detail-type
    # under test is checked for absence.
    leftover = _poll_sqs_for_type(sqs, queue_url, "Restore Job State Change", timeout_s=30.0)
    assert leftover == [], f"no Restore Job State Change event should be delivered, got {leftover}"

    # Sanity: the real backup job is still progressing normally -- already proven
    # live above via its delivered "Backup Job State Change" event.
    job_state = backup.describe_backup_job(BackupJobId=backup_job_id)["State"]
    assert job_state in {"CREATED", "PENDING", "RUNNING", "COMPLETED"}, (
        f"the control backup job is in state {job_state!r}, not progressing normally"
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


def _delete_table_if_exists(ctx, table_name: str) -> None:
    ddb = ctx.client("dynamodb")
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-beh-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name)
    ctx.on_cleanup(lambda: _cleanup_vault(backup, name))
    return name, resp["BackupVaultArn"]


# budget.cleanup_timeout for behavioral/backup__events, shared by this check's teardowns.
_TEARDOWN_RETRY_S = 900.0


def _stop_if_active(backup, job_id: str) -> None:
    """Teardown: abort the control backup job while it is still active."""
    state = backup.describe_backup_job(BackupJobId=job_id)["State"]
    if state in ("CREATED", "PENDING", "RUNNING"):
        backup.stop_backup_job(BackupJobId=job_id)


def _cleanup_vault(backup, vault_name: str) -> None:
    """Delete the vault's recovery points, then the vault. The control backup job keeps the vault
    refusing deletion (InvalidRequestException) until it finishes, so that refusal is retried
    every 2 s to the cleanup deadline, re-deleting any recovery point the job produced."""
    deadline = time.monotonic() + _TEARDOWN_RETRY_S - 120.0
    while True:
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
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            busy = err["Code"] == "InvalidRequestException" and err.get("Message", "").startswith(
                "Backup vault cannot be deleted (contains "
            )
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_backup_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-beh-bkuprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    ]
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_arns))
    return role_arn


def _start_backup_job_with_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0
) -> str:
    """IAM is eventually consistent: a freshly created role may not yet be assumable by the
    backup service. Poll the real condition (StartBackupJob succeeding) rather than sleeping
    a fixed duration."""
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


def _wait_for_event_matching(
    sqs, queue_url: str, match_fn, timeout_s: float = 60.0, interval_s: float = 3.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 5.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s")


def _poll_sqs_for_type(sqs, queue_url: str, detail_type: str, timeout_s: float = 30.0) -> list[dict[str, Any]]:
    """Drain the queue for timeout_s, returning only messages matching detail_type.
    Messages of any other detail-type (e.g. unrelated real traffic sharing this
    queue) are drained and discarded, not treated as a match."""
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            body = json.loads(m["Body"])
            if body.get("detail-type") == detail_type:
                out.append(body)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


