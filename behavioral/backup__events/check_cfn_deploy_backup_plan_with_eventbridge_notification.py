"""cfn-deploy-backup-plan-with-eventbridge-notification."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-backup-plan-with-eventbridge-notification"
GROUP = "deployment-order"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a stack with a backup plan and a rule on aws.backup job-state events, an on-demand job
    that reaches COMPLETED delivers its terminal notification to the target with the right
    source, detail-type, job id, vault name and state."""
    backup = ctx.client("backup")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    table_name = _xname(ctx, "tbl")
    vault_name = _xname(ctx, "vault")
    svc_role_name = _xname(ctx, "backupsvc")
    plan_name = _xname(ctx, "plan")
    sel_name = _xname(ctx, "sel")
    queue_name = _xname(ctx, "notifyq")
    rule_name = _xname(ctx, "notifyrule")

    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
    svc_role_arn = f"arn:aws:iam::{account_id}:role/{svc_role_name}"
    queue_arn = f"arn:aws:sqs:{region}:{account_id}:{queue_name}"
    rule_arn = f"arn:aws:events:{region}:{account_id}:rule/{rule_name}"

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "BackupTable": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": table_name,
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    },
                },
                "BackupVault": {
                    "Type": "AWS::Backup::BackupVault",
                    "Properties": {"BackupVaultName": vault_name},
                },
                "BackupSvcRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": svc_role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "backup.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
                        ],
                    },
                },
                "BackupPlan": {
                    "Type": "AWS::Backup::BackupPlan",
                    "Properties": {
                        "BackupPlan": {
                            "BackupPlanName": plan_name,
                            "BackupPlanRule": [
                                {
                                    "RuleName": "daily",
                                    "TargetBackupVault": vault_name,
                                    "ScheduleExpression": "cron(0 5 * * ? *)",
                                }
                            ],
                        }
                    },
                    "DependsOn": ["BackupVault"],
                },
                "BackupSelection": {
                    "Type": "AWS::Backup::BackupSelection",
                    "Properties": {
                        "BackupPlanId": {"Ref": "BackupPlan"},
                        "BackupSelection": {
                            "SelectionName": sel_name,
                            "IamRoleArn": svc_role_arn,
                            "Resources": [table_arn],
                        },
                    },
                    "DependsOn": ["BackupSvcRole", "BackupTable"],
                },
                "NotifyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": queue_name},
                },
                "NotifyQueuePolicy": {
                    "Type": "AWS::SQS::QueuePolicy",
                    "Properties": {
                        "Queues": [{"Ref": "NotifyQueue"}],
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": "sqs:SendMessage",
                                    "Resource": queue_arn,
                                    "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                                }
                            ],
                        },
                    },
                },
                "NotifyRule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": rule_name,
                        "EventPattern": {
                            "source": ["aws.backup"],
                            "detail-type": ["Backup Job State Change"],
                        },
                        "Targets": [{"Id": "notify-queue", "Arn": queue_arn}],
                    },
                    "DependsOn": ["NotifyQueuePolicy"],
                },
            },
        }
    )

    _deploy_cfn(ctx, template, capabilities=["CAPABILITY_NAMED_IAM"])

    # Verify the rule/target is correctly wired after stack creation.
    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert len(targets) == 1, f"expected exactly 1 target, got {targets}"
    assert targets[0]["Arn"] == queue_arn, f"expected target arn {queue_arn!r}, got {targets[0]['Arn']!r}"

    # Kick off a real on-demand backup job (IAM role propagation for a freshly
    # created role can lag a few seconds, so retry briefly).
    job_id = _start_backup_job_with_retry(backup, vault_name, table_arn, svc_role_arn)

    # Register recovery-point cleanup now that we know the job id. Registered
    # AFTER _deploy_cfn's stack-delete teardown, so it runs FIRST (LIFO) and the
    # vault is empty by the time the stack tries to delete it.
    ctx.on_cleanup(lambda: _cleanup_backup_job_recovery_point(ctx, vault_name, job_id))

    # A "Backup Job State Change" event fires on every transition (e.g. CREATED,
    # RUNNING, COMPLETED) — waiting for the job's own terminal state first, then
    # matching the SQS-delivered event to that same state, proves the notification
    # actually reflects the outcome rather than just an early, non-terminal beat.
    job = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id),
        lambda j: j["State"] in {"COMPLETED", "FAILED", "ABORTED", "EXPIRED"},
        timeout_s=240.0,
        interval_s=5.0,
        description=f"backup job {job_id} reaching a terminal state",
    )
    assert job["State"] == "COMPLETED", f"expected backup job to complete, got {job['State']!r}"

    # Observe the actual downstream effect: the job's COMPLETED state-change event
    # lands on the wired SQS target with the right envelope and payload.
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    envelope = _poll_for_backup_event(sqs, queue_url, job_id, expected_state="COMPLETED", timeout_s=180.0)
    detail = envelope["detail"]
    assert detail["backupJobId"] == job_id, f"expected backupJobId {job_id!r}, got {detail.get('backupJobId')!r}"
    assert detail["backupVaultName"] == vault_name, f"expected vault {vault_name!r}, got {detail.get('backupVaultName')!r}"
    assert envelope["source"] == "aws.backup", f"expected source 'aws.backup', got {envelope.get('source')!r}"
    assert envelope["detail-type"] == "Backup Job State Change", (
        f"expected detail-type 'Backup Job State Change', got {envelope.get('detail-type')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=540,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _start_backup_job_with_retry(backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 30.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )
            return resp["BackupJobId"]
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"start_backup_job never succeeded: {last_err}")


def _cleanup_backup_job_recovery_point(ctx, vault_name: str, job_id: str) -> None:
    backup = ctx.client("backup")
    try:
        job = _poll_until(
            lambda: backup.describe_backup_job(BackupJobId=job_id),
            lambda j: j["State"] in {"COMPLETED", "FAILED", "ABORTED", "EXPIRED"},
            timeout_s=240.0,
            interval_s=5.0,
            description=f"backup job {job_id} terminal state",
        )
    except AssertionError:
        return
    rp_arn = job.get("RecoveryPointArn")
    if rp_arn:
        try:
            backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _poll_for_backup_event(
    sqs, queue_url: str, job_id: str, expected_state: str, timeout_s: float = 180.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    seen_states: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            detail = (envelope or {}).get("detail", {})
            if detail.get("backupJobId") == job_id:
                seen_states.append(detail.get("state"))
                if detail.get("state") == expected_state:
                    return envelope
    raise AssertionError(
        f"no {expected_state!r} Backup Job State Change event for job {job_id} within "
        f"{timeout_s}s (saw states {seen_states!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
