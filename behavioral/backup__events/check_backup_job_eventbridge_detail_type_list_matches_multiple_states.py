"""backup-job-eventbridge-detail-type-list-matches-multiple-states."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "backup-job-eventbridge-detail-type-list-matches-multiple-states"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule listing both 'Backup Job State Change' and 'Copy Job State Change' detail-types
    matches the events of a real backup job and of the copy job started from its recovery point,
    and delivers both to one SQS target."""
    # One teardown deadline per run, shared by every vault teardown.
    teardown_deadline: dict = {}
    backup = ctx.client("backup")

    role_arn = _create_backup_role(ctx)
    table_arn = _create_backup_table(ctx)
    src_vault_name, src_vault_arn = _create_backup_vault(ctx, teardown_deadline)
    dst_vault_name, dst_vault_arn = _create_backup_vault(ctx, teardown_deadline)

    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["aws.backup"],
            "detail-type": ["Backup Job State Change", "Copy Job State Change"],
        },
    )
    queue_url, queue_arn = _create_queue_for_rule(ctx, [rule_arn])
    _bind_target(ctx, rule_name, queue_arn)

    backup_job_id, recovery_point_arn = _run_backup_job_until_completed(
        backup, src_vault_name, table_arn, role_arn
    )

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
        interval_s=10.0,
        description=f"copy job {copy_job_id} terminal state",
    )
    assert copy_final == "COMPLETED", f"copy job ended in {copy_final}, expected COMPLETED"

    terminal = _wait_for_terminal_events(
        ctx,
        queue_url,
        {
            "Backup Job State Change": ("backupJobId", backup_job_id),
            "Copy Job State Change": ("copyJobId", copy_job_id),
        },
        timeout_s=180.0,
    )

    assert set(terminal) == {"Backup Job State Change", "Copy Job State Change"}, (
        f"expected both detail-types delivered by the single rule, got {sorted(terminal)}"
    )
    assert terminal["Backup Job State Change"]["detail"]["state"] == "COMPLETED", (
        f"expected COMPLETED, got {terminal['Backup Job State Change']['detail'].get('state')!r}"
    )
    assert terminal["Copy Job State Change"]["detail"]["state"] == "COMPLETED", (
        f"expected COMPLETED, got {terminal['Copy Job State Change']['detail'].get('state')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bkp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
    table_name = ctx.unique_name("sim2real-bkp-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
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
    vault_name = ctx.unique_name("sim2real-bkp-vault-")
    resp = backup.create_backup_vault(BackupVaultName=vault_name)
    ctx.on_cleanup(lambda: _empty_and_delete_vault(backup, vault_name, teardown_deadline))
    return vault_name, resp["BackupVaultArn"]


def _start_backup_job_with_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0
) -> str:
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


def _run_backup_job_until_completed(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 2400.0
) -> tuple[str, str]:
    """A freshly created DynamoDB table is not immediately backup-eligible: AWS Backup answers
    a real, terminal FAILED job with StatusMessage 'Backups are being enabled for the table...
    Please retry later' for a window after CreateTable. That is DynamoDB's own eventual
    consistency, not a check defect, so retry a fresh job against the *measured* real condition
    (the specific warm-up message) rather than masking any other FAILED reason."""
    deadline = time.monotonic() + timeout_s
    last_detail = None
    while time.monotonic() < deadline:
        job_id = _start_backup_job_with_retry(backup, vault_name, resource_arn, role_arn)
        final = _poll_until(
            lambda: backup.describe_backup_job(BackupJobId=job_id)["State"],
            lambda s: s in ("COMPLETED", "FAILED", "ABORTED"),
            timeout_s=1200,
            interval_s=10.0,
            description=f"backup job {job_id} terminal state",
        )
        job = backup.describe_backup_job(BackupJobId=job_id)
        if final == "COMPLETED":
            return job_id, job["RecoveryPointArn"]
        last_detail = job.get("StatusMessage")
        if final == "FAILED" and last_detail and "being enabled for the table" in last_detail:
            time.sleep(2.0)
            continue
        raise AssertionError(f"backup job {job_id} ended in {final}, expected COMPLETED: {last_detail!r}")
    raise AssertionError(
        f"table never became backup-eligible within {timeout_s}s: {last_detail!r}"
    )


def _wait_for_terminal_events(
    ctx, queue_url: str, expectations: dict[str, tuple[str, str]], timeout_s: float = 180.0
) -> dict[str, dict]:
    """AWS Backup emits one 'Backup Job State Change' / 'Copy Job State Change' event per state
    transition (observed: PENDING, then the terminal state), not one event per job -- so the
    first message of a detail-type is not necessarily the terminal one. Drain until each
    expected (detail-type, id) pair has produced a message in a terminal state, keyed by the
    job/copy id so a stale event from an earlier retried attempt is never mistaken for this
    run's terminal event."""
    sqs = ctx.client("sqs")
    terminal_states = {"COMPLETED", "FAILED", "ABORTED"}
    found: dict[str, dict] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(found) < len(expectations):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            detail_type = body.get("detail-type")
            expectation = expectations.get(detail_type)
            if expectation is None or detail_type in found:
                continue
            id_field, expected_id = expectation
            detail = body.get("detail", {})
            if detail.get(id_field) == expected_id and detail.get("state") in terminal_states:
                found[detail_type] = body
    return found


def _create_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-bkp-rule-")
    arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")[
        "RuleArn"
    ]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return name, arn


def _create_queue_for_rule(ctx, rule_arns: list[str]) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-bkp-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    source_arn_condition = rule_arns[0] if len(rule_arns) == 1 else rule_arns
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn_condition}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _bind_target(ctx, rule_name: str, target_arn: str, target_id: str = "target-1") -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
