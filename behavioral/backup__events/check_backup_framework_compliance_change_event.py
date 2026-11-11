"""backup-framework-compliance-change-event."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "backup-framework-compliance-change-event"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Creating and updating a Backup Audit Manager framework emits no framework or compliance
    EventBridge event (the documented event catalog has none), while updating a backup plan on
    the same rule and queue delivers the documented 'Backup Plan State Change' event."""
    events = ctx.client("events")
    backup = ctx.client("backup")

    plan_rule_name = ctx.unique_name("sim2real-rule-plan-")
    plan_pattern = {"source": ["aws.backup"], "detail-type": ["Backup Plan State Change"]}
    plan_rule_arn = events.put_rule(Name=plan_rule_name, EventPattern=json.dumps(plan_pattern))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=plan_rule_name))
    plan_queue = _create_events_queue(ctx, plan_rule_arn)
    events.put_targets(Rule=plan_rule_name, Targets=[{"Id": "t1", "Arn": plan_queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=plan_rule_name, Ids=["t1"]))

    # Any hypothetical framework/compliance detail-type an emulator might (wrongly) invent.
    framework_rule_name = ctx.unique_name("sim2real-rule-framework-")
    framework_pattern = {
        "source": ["aws.backup"],
        "detail-type": [
            "Backup Framework State Change",
            "Framework State Change",
            "Backup Compliance State Change",
            "Backup Framework Compliance State Change",
            "Framework Compliance State Change",
        ],
    }
    framework_rule_arn = events.put_rule(
        Name=framework_rule_name, EventPattern=json.dumps(framework_pattern)
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=framework_rule_name))
    framework_queue = _create_events_queue(ctx, framework_rule_arn)
    events.put_targets(Rule=framework_rule_name, Targets=[{"Id": "t1", "Arn": framework_queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=framework_rule_name, Ids=["t1"]))

    vault_name, _vault_arn = _create_backup_vault(ctx)

    framework_name = ctx.unique_name("sim2realframework")
    # AWS Backup rejects CreateFramework with AlreadyExistsException when a framework with the
    # SAME controls/configuration already exists ANYWHERE in the account, regardless of
    # FrameworkName. A fixed retention-days literal collides with
    # any other framework (this check's own prior run, or a concurrent tenant's) carrying the
    # same control, so the value is randomized per run to keep the control content unique.
    retention_days = str(random.randint(30, 365))
    backup.create_framework(
        FrameworkName=framework_name,
        FrameworkControls=[
            {
                "ControlName": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK",
                "ControlInputParameters": [
                    {"ParameterName": "requiredRetentionDays", "ParameterValue": retention_days}
                ],
                "ControlScope": {},
            }
        ],
    )
    ctx.on_cleanup(lambda: backup.delete_framework(FrameworkName=framework_name))
    # DeploymentStatus must leave the transient CREATE_IN_PROGRESS state before a
    # subsequent UpdateFramework is accepted, else AWS Backup answers ConflictException
    # ("concurrent update for the framework").
    _wait_until(
        lambda: backup.describe_framework(FrameworkName=framework_name)["DeploymentStatus"],
        lambda status: status in ("COMPLETED", "FAILED"),
        timeout_s=120.0,
        description="framework DeploymentStatus leaves CREATE_IN_PROGRESS",
    )
    backup.update_framework(FrameworkName=framework_name, FrameworkDescription="sim2real updated description")

    plan_id = _create_plan(ctx, backup, vault_name)
    _update_plan(backup, plan_id, vault_name)

    plan_event = _wait_for_event_matching(
        ctx, plan_queue["url"], lambda evt: evt.get("detail", {}).get("backupPlanId") == plan_id, timeout_s=90.0, interval_s=5.0
    )
    assert plan_event["detail-type"] == "Backup Plan State Change", (
        f"expected detail-type 'Backup Plan State Change', got {plan_event['detail-type']!r}"
    )
    assert plan_event["detail"]["state"] == "MODIFIED", (
        f"expected plan event state 'MODIFIED', got {plan_event['detail'].get('state')!r}"
    )

    _assert_no_message(ctx, framework_queue["url"], duration_s=20.0)


def _wait_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0, description: str = "condition") -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_backup_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-vault-")
    resp = backup.create_backup_vault(BackupVaultName=vault_name)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))
    return vault_name, resp["BackupVaultArn"]


def _create_plan(ctx, backup, vault_name: str) -> str:
    plan_name = ctx.unique_name("sim2real_plan_")
    resp = backup.create_backup_plan(
        BackupPlan={
            "BackupPlanName": plan_name,
            "Rules": [
                {
                    "RuleName": "rule1",
                    "TargetBackupVaultName": vault_name,
                    "ScheduleExpression": "cron(0 5 * * ? *)",
                    "StartWindowMinutes": 60,
                    "CompletionWindowMinutes": 120,
                }
            ],
        }
    )
    plan_id = resp["BackupPlanId"]
    ctx.on_cleanup(lambda: backup.delete_backup_plan(BackupPlanId=plan_id))
    return plan_id


def _update_plan(backup, plan_id: str, vault_name: str) -> None:
    backup.update_backup_plan(
        BackupPlanId=plan_id,
        BackupPlan={
            "BackupPlanName": "sim2real-updated-plan",
            "Rules": [
                {
                    "RuleName": "rule1",
                    "TargetBackupVaultName": vault_name,
                    "ScheduleExpression": "cron(0 6 * * ? *)",
                    "StartWindowMinutes": 90,
                    "CompletionWindowMinutes": 180,
                }
            ],
        },
    )


def _create_events_queue(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evtq-"))["QueueUrl"]
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


def _assert_no_message(ctx, queue_url: str, duration_s: float = 20.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            raise AssertionError(f"a framework/compliance-shaped event was unexpectedly emitted: {body}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
