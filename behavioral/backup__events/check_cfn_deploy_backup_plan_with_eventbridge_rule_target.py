"""cfn-deploy-backup-plan-with-eventbridge-rule-target."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-backup-plan-with-eventbridge-rule-target"
GROUP = "deployment-order"
SERVICES = ["backup", "events"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "VaultName": {"Type": "String"},
            "TableName": {"Type": "String"},
            "TopicName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "RoleName": {"Type": "String"},
            "RuleName": {"Type": "String"},
        },
        "Resources": {
            "BackupVault": {
                "Type": "AWS::Backup::BackupVault",
                "Properties": {"BackupVaultName": {"Ref": "VaultName"}},
            },
            "BackupTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": {"Ref": "TableName"},
                    "AttributeDefinitions": [
                        {"AttributeName": "id", "AttributeType": "S"}
                    ],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                },
            },
            "BackupRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
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
            "AlarmTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": {"Ref": "TopicName"}},
            },
            "NotifyQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            },
            "QueueSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "AlarmTopic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["NotifyQueue", "Arn"]},
                    "RawMessageDelivery": True,
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "NotifyQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["NotifyQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {"aws:SourceArn": {"Ref": "AlarmTopic"}}
                                },
                            }
                        ],
                    },
                },
            },
            "TopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": [{"Ref": "AlarmTopic"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "AlarmTopic"},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {
                                            "Fn::GetAtt": ["BackupEventRule", "Arn"]
                                        }
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "BackupEventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Ref": "RuleName"},
                    "EventPattern": {
                        "source": ["aws.backup"],
                        "detail-type": ["Backup Job State Change"],
                    },
                    "Targets": [{"Id": "AlarmTopicTarget", "Arn": {"Ref": "AlarmTopic"}}],
                },
            },
        },
        "Outputs": {
            "VaultName": {"Value": {"Ref": "BackupVault"}},
            "TableArn": {"Value": {"Fn::GetAtt": ["BackupTable", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["BackupRole", "Arn"]}},
            "TopicArn": {"Value": {"Ref": "AlarmTopic"}},
            "QueueUrl": {"Value": {"Ref": "NotifyQueue"}},
        },
    }
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Backup plan/vault + EventBridge rule -> SNS -> SQS pipeline delivers a
    real 'Backup Job State Change' event (state=COMPLETED) once an actual on-demand backup job
    on a DynamoDB table finishes."""
    params = {
        "VaultName": _xname(ctx, "vault"),
        "TableName": _xname(ctx, "table"),
        "TopicName": _xname(ctx, "topic"),
        "QueueName": _xname(ctx, "queue"),
        "RoleName": _xname(ctx, "role"),
        "RuleName": _xname(ctx, "rule"),
    }
    stack = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=300)
    outputs = stack["outputs"]
    table_arn = outputs["TableArn"]
    role_arn = outputs["RoleArn"]
    vault_name = outputs["VaultName"]
    queue_url = outputs["QueueUrl"]
    # An on-demand StartBackupJob below leaves a recovery point in the vault, and
    # AWS::Backup::BackupVault can only be deleted once empty — clear it before the
    # stack-delete cleanup (registered inside _deploy_cfn) runs, which LIFO ordering
    # guarantees since this is registered after.
    ctx.on_cleanup(lambda: _delete_all_recovery_points(ctx, vault_name))

    backup = ctx.client("backup")
    sqs = ctx.client("sqs")

    # Freshly-created IAM role can lag propagation; retry the StartBackupJob call.
    def _try_start():
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=table_arn, IamRoleArn=role_arn
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidParameterValueException", "AccessDeniedException"):
                return None
            raise

    start_resp = _poll_until(
        _try_start,
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5.0,
        description="StartBackupJob to succeed once IAM role propagates",
    )
    job_id = start_resp["BackupJobId"]

    final_job = _poll_until(
        lambda: backup.describe_backup_job(BackupJobId=job_id),
        lambda j: j["State"] in ("COMPLETED", "ABORTED", "FAILED"),
        timeout_s=900,
        interval_s=15.0,
        description=f"backup job {job_id} reach terminal state",
    )
    assert final_job["State"] == "COMPLETED", f"backup job ended in {final_job['State']!r}"

    def _poll_queue_for_job():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            if body.get("detail", {}).get("backupJobId") == job_id and body["detail"][
                "state"
            ] == "COMPLETED":
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return None

    delivered = _poll_until(
        _poll_queue_for_job,
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5.0,
        description="COMPLETED Backup Job State Change event delivered via SNS->SQS",
    )
    assert delivered["detail"]["backupJobId"] == job_id, (
        f"expected event for job {job_id!r}, got {delivered['detail'].get('backupJobId')!r}"
    )
    assert delivered["detail"]["state"] == "COMPLETED", (
        f"expected state COMPLETED, got {delivered['detail'].get('state')!r}"
    )
    assert delivered["source"] == "aws.backup", f"expected source aws.backup, got {delivered['source']!r}"
    assert delivered["detail-type"] == "Backup Job State Change", (
        f"expected detail-type 'Backup Job State Change', got {delivered['detail-type']!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"


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
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _delete_all_recovery_points(ctx, vault_name: str) -> None:
    """AWS::Backup::BackupVault can only be deleted (by the stack teardown) once it is
    empty — a completed on-demand job leaves a recovery point behind, so remove those first."""
    backup = ctx.client("backup")

    def _rps():
        try:
            return backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get(
                "RecoveryPoints", []
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        rps = _rps()
        if not rps:
            return
        for rp in rps:
            try:
                backup.delete_recovery_point(
                    BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException" and not _deleting(exc):
                    raise
        time.sleep(2.0)
    raise AssertionError(f"vault {vault_name} still holds recovery points 240 s after DeleteRecoveryPoint")


def _deleting(exc: ClientError) -> bool:
    """A recovery point whose deletion already started is refused again until it is gone."""
    err = exc.response["Error"]
    return err["Code"] == "InvalidRequestException" and "already started the deletion" in err.get("Message", "")


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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
