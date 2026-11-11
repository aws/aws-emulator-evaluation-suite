"""copy-job-state-change-event-delivered."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "copy-job-state-change-event-delivered"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartCopyJob on a nonexistent recovery point is rejected synchronously and creates no copy
    job, so no 'Copy Job State Change' event reaches the rule's target."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    backup = ctx.client("backup")

    account = ctx.client("sts").get_caller_identity()["Account"]

    table_name, table_arn = _create_table(ctx)
    source_vault_name, source_vault_arn = _create_vault(ctx)
    dest_vault_name, dest_vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)

    queue_url, queue_arn = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {"source": ["aws.backup"], "detail-type": ["Copy Job State Change"]}
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["sqs-target"]))

    _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])

    fake_recovery_point_arn = (
        f"arn:aws:backup:{ctx.region}:{account}:recovery-point:00000000-0000-0000-0000-000000000000"
    )
    error_code, error_message = _start_copy_job_error(
        backup,
        RecoveryPointArn=fake_recovery_point_arn,
        SourceBackupVaultName=source_vault_name,
        DestinationBackupVaultArn=dest_vault_arn,
        IamRoleArn=backup_role_arn,
    )
    assert error_code == "ResourceNotFoundException", (
        f"expected StartCopyJob against a nonexistent recovery point to be rejected synchronously "
        f"with ResourceNotFoundException, got {error_code!r} ({error_message!r})"
    )
    expected_message = "Cannot find recovery point"
    assert error_message == expected_message, (
        f"ResourceNotFoundException message {error_message!r}, expected {expected_message!r}"
    )

    # Nothing should ever land on the queue for a copy job that was never created.
    leftover = _poll_sqs(sqs, queue_url, min_count=1, timeout_s=30.0)
    assert leftover == [], f"no Copy Job State Change event should be delivered, got {leftover}"

    # Sanity: the source table/vault/role setup is otherwise valid -- a real
    # backup job against them is accepted (even though we don't wait it out).
    backup_job_id = _start_backup_job_with_role_retry(
        backup, BackupVaultName=source_vault_name, ResourceArn=table_arn, IamRoleArn=backup_role_arn
    )["BackupJobId"]
    backup_job_state = backup.describe_backup_job(BackupJobId=backup_job_id)["State"]
    assert backup_job_state in {"CREATED", "PENDING", "RUNNING", "COMPLETED"}, (
        f"expected a real on-demand backup job against the same vault/role setup to be accepted, "
        f"got State={backup_job_state!r}"
    )


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-beh-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-beh-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name, BackupVaultTags={"sim2real": CHECK})
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
    role_name = ctx.unique_name("sim2real-beh-bkuprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    ]
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_arns))
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


_ROLE_NOT_ASSUMABLE = "IAM Role cannot be assumed by AWS Backup"


def _start_copy_job_error(backup, **kwargs) -> tuple[str, str]:
    """A freshly-created backup service role can lag IAM/STS propagation, which surfaces as
    AccessDeniedException, or as InvalidParameterValueException "IAM Role cannot be assumed by
    AWS Backup", before the target ever evaluates RecoveryPointArn. Retry only those, bounded,
    so a real target is not penalized for a race in the check's own setup;
    any other rejection is the synchronous-refusal boundary this check exists to observe, and
    is returned immediately, as (code, message), rather than retried. A SUCCESS raises."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            result = backup.start_copy_job(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            propagating = code == "AccessDeniedException" or (
                code == "InvalidParameterValueException"
                and exc.response["Error"].get("Message") == _ROLE_NOT_ASSUMABLE
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            return code, exc.response["Error"].get("Message", "")
        raise AssertionError(
            f"StartCopyJob of a nonexistent recovery point SUCCEEDED and returned {result!r}"
        )


def _start_backup_job_with_role_retry(backup, **kwargs) -> dict[str, Any]:
    """Same role-propagation race as _start_copy_job_error, but this call is expected to
    succeed, so any propagation-shaped rejection is retried until it does."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return backup.start_backup_job(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in {"AccessDeniedException", "InvalidParameterValueException"} and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-beh-q-"), tags={"sim2real": CHECK})["QueueUrl"]
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


def _poll_sqs(sqs, queue_url: str, min_count: int = 1, timeout_s: float = 30.0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


