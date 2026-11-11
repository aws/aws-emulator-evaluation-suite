"""cfn-deploy-backup-eventbridge-target-missing-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-backup-eventbridge-target-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Of two Step Functions targets of one scheduled rule, the one whose role holds
    backup:StartBackupJob starts a real backup job and the one whose role lacks it is denied and
    starts none."""
    backup = ctx.client("backup")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    table_name = _xname(ctx, "tbl")
    vault_name = _xname(ctx, "vault")
    backup_svc_role_name = _xname(ctx, "backupsvc")
    good_role_name = _xname(ctx, "sfngood")
    bad_role_name = _xname(ctx, "sfnbad")
    good_sm_name = _xname(ctx, "smgood")
    bad_sm_name = _xname(ctx, "smbad")
    events_role_name = _xname(ctx, "eventsrole")
    rule_name = _xname(ctx, "rule")

    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
    backup_svc_role_arn = f"arn:aws:iam::{account_id}:role/{backup_svc_role_name}"
    good_role_arn = f"arn:aws:iam::{account_id}:role/{good_role_name}"
    bad_role_arn = f"arn:aws:iam::{account_id}:role/{bad_role_name}"
    good_sm_arn = f"arn:aws:states:{region}:{account_id}:stateMachine:{good_sm_name}"
    bad_sm_arn = f"arn:aws:states:{region}:{account_id}:stateMachine:{bad_sm_name}"
    events_role_arn = f"arn:aws:iam::{account_id}:role/{events_role_name}"

    def _task_definition(vault: str, resource_arn: str, role_arn: str) -> dict[str, Any]:
        return {
            "StartAt": "StartBackup",
            "States": {
                "StartBackup": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:backup:startBackupJob",
                    "Parameters": {
                        "BackupVaultName": vault,
                        "ResourceArn": resource_arn,
                        "IamRoleArn": role_arn,
                    },
                    "End": True,
                }
            },
        }

    trust = lambda svc: {  # noqa: E731
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}],
    }

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
                        "RoleName": backup_svc_role_name,
                        "AssumeRolePolicyDocument": trust("backup.amazonaws.com"),
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
                        ],
                    },
                },
                "SfnGoodRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": good_role_name,
                        "AssumeRolePolicyDocument": trust("states.amazonaws.com"),
                        "Policies": [
                            {
                                "PolicyName": "start-backup",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "backup:StartBackupJob",
                                            "Resource": "*",
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": "iam:PassRole",
                                            "Resource": backup_svc_role_arn,
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "SfnBadRole": {
                    # Deliberately: trust only, no backup:StartBackupJob permission.
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": bad_role_name,
                        "AssumeRolePolicyDocument": trust("states.amazonaws.com"),
                    },
                },
                "SfnGood": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": good_sm_name,
                        "RoleArn": good_role_arn,
                        "DefinitionString": json.dumps(
                            _task_definition(vault_name, table_arn, backup_svc_role_arn)
                        ),
                    },
                    "DependsOn": ["SfnGoodRole"],
                },
                "SfnBad": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": bad_sm_name,
                        "RoleArn": bad_role_arn,
                        "DefinitionString": json.dumps(
                            _task_definition(vault_name, table_arn, backup_svc_role_arn)
                        ),
                    },
                    "DependsOn": ["SfnBadRole"],
                },
                "EventsRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": events_role_name,
                        "AssumeRolePolicyDocument": trust("events.amazonaws.com"),
                        "Policies": [
                            {
                                "PolicyName": "invoke-sfn",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "states:StartExecution",
                                            "Resource": [good_sm_arn, bad_sm_arn],
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": rule_name,
                        "ScheduleExpression": "rate(1 minute)",
                        "Targets": [
                            {"Id": "good", "Arn": good_sm_arn, "RoleArn": events_role_arn},
                            {"Id": "bad", "Arn": bad_sm_arn, "RoleArn": events_role_arn},
                        ],
                    },
                    "DependsOn": ["SfnGood", "SfnBad", "EventsRole"],
                },
            },
        }
    )

    _deploy_cfn(ctx, template, capabilities=["CAPABILITY_NAMED_IAM"])

    # (a) The specific, exact IAM policy shape: the bad role's inline policy set
    # (attached by the stack) grants no backup:StartBackupJob permission at all,
    # while the good role's does. We assert this directly off the live role
    # policies rather than through the policy simulator, whose caching lag can
    # exceed the propagation delay of the real enforcement path we exercise below.
    bad_policy_names = iam.list_role_policies(RoleName=bad_role_name)["PolicyNames"]
    assert bad_policy_names == [], f"expected no inline policies on the bad role, got {bad_policy_names}"
    good_policy_names = iam.list_role_policies(RoleName=good_role_name)["PolicyNames"]
    good_policy_doc = iam.get_role_policy(RoleName=good_role_name, PolicyName=good_policy_names[0])["PolicyDocument"]
    good_actions = {
        a
        for stmt in good_policy_doc["Statement"]
        for a in (stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]])
    }
    assert "backup:StartBackupJob" in good_actions, good_policy_doc

    # (c) Positive control, in the same file: the good target's scheduled
    # execution actually succeeds and starts a real backup job.
    good_execution = _poll_until(
        lambda: _latest_execution(sfn, good_sm_arn),
        lambda e: e is not None and e["status"] in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=260.0,
        interval_s=10.0,
        description="good-target scheduled execution to reach a terminal state",
    )
    assert good_execution["status"] == "SUCCEEDED", (
        f"expected the good target's scheduled execution to SUCCEED, got {good_execution['status']}"
    )
    good_output = json.loads(sfn.describe_execution(executionArn=good_execution["executionArn"])["output"])
    job_id = good_output["BackupJobId"]
    ctx.on_cleanup(lambda: _cleanup_backup_job_recovery_point(ctx, vault_name, job_id))
    job = backup.describe_backup_job(BackupJobId=job_id)
    assert job["ResourceArn"] == table_arn, (
        f"expected backup job {job_id} to target {table_arn}, got {job['ResourceArn']}"
    )

    # (b) The effect is absent for the bad target: its execution fails, and no
    # second backup job for this table was ever created.
    bad_execution = _poll_until(
        lambda: _latest_execution(sfn, bad_sm_arn),
        lambda e: e is not None and e["status"] in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=260.0,
        interval_s=10.0,
        description="bad-target scheduled execution to reach a terminal state",
    )
    assert bad_execution["status"] == "FAILED", (
        f"expected the under-permissioned target's scheduled execution to FAIL, got {bad_execution['status']}"
    )
    bad_detail = sfn.describe_execution(executionArn=bad_execution["executionArn"])
    bad_cause = bad_detail.get("cause", "")
    assert "not authorized to perform: backup:StartBackupJob" in bad_cause, (
        f"expected the failure cause to name an unauthorized backup:StartBackupJob call, "
        f"got error={bad_detail.get('error')!r} cause={bad_cause!r}"
    )

    jobs_for_table = backup.list_backup_jobs(ByResourceArn=table_arn)["BackupJobs"]
    assert len(jobs_for_table) == 1, f"expected only the good job, got {jobs_for_table}"
    assert jobs_for_table[0]["BackupJobId"] == job_id, (
        f"expected the only backup job for {table_arn} to be the good one {job_id}, "
        f"got {jobs_for_table[0]['BackupJobId']}"
    )


def _latest_execution(sfn, state_machine_arn: str) -> dict[str, Any] | None:
    execs = sfn.list_executions(stateMachineArn=state_machine_arn, maxResults=5)["executions"]
    if not execs:
        return None
    return sorted(execs, key=lambda e: e["startDate"])[-1]


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
        timeout_s=120,
        interval_s=5.0,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
