"""deploy-log-retention-set-via-template."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-log-retention-set-via-template"
GROUP = "deployment-wiring"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A template's AWS::Logs::LogGroup RetentionInDays is applied to the deployed log group.
    Deployment goes through a change set, so acceptance and application are asserted separately."""
    function_name = _xname(ctx, "fn")
    role_name = _xname(ctx, "role")
    retention_days = 3
    template = _build_template(function_name=function_name, role_name=role_name, retention_days=retention_days)
    stack = _deploy_cfn(ctx, template)
    log_group_name = stack["outputs"]["LogGroupName"]
    assert log_group_name == f"/aws/lambda/{function_name}"

    logs = ctx.client("logs")
    resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    groups = [g for g in resp["logGroups"] if g["logGroupName"] == log_group_name]
    assert len(groups) == 1, f"expected exactly one log group named {log_group_name}, got {groups}"
    assert groups[0]["retentionInDays"] == retention_days, (
        f"expected retentionInDays={retention_days} on the deployed log group, "
        f"got {groups[0].get('retentionInDays')!r}"
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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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
    """Deploy via a change set, asserting it adds LogGroup before executing it.
    CreateChangeSet only previews the template; resources exist only after ExecuteChangeSet."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    change_set_name = _xname(ctx, "cs")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "ChangeSetName": change_set_name,
        "ChangeSetType": "CREATE",
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_change_set(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))

    cs = _poll_until(
        lambda: cfn.describe_change_set(StackName=name, ChangeSetName=change_set_name),
        lambda c: c["Status"] in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=120,
        interval_s=5.0,
        description=f"change set {change_set_name} create",
    )
    assert cs["Status"] == "CREATE_COMPLETE", (
        f"change set {change_set_name} ended in {cs['Status']}: {cs.get('StatusReason')}"
    )
    changes_by_id = {
        c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"]["Action"] for c in cs.get("Changes", [])
    }
    assert changes_by_id.get("LogGroup") == "Add", (
        f"expected CreateChangeSet to accept an Add of LogGroup, got {changes_by_id}"
    )

    cfn.execute_change_set(StackName=name, ChangeSetName=change_set_name)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name} execute change set",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack["StackId"], "outputs": outputs}


_HANDLER_CODE = """def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
"""


def _build_template(*, function_name: str, role_name: str, retention_days: int) -> str:
    log_group_name = f"/aws/lambda/{function_name}"
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                },
            },
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name, "RetentionInDays": retention_days},
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["ExecRole", "LogGroup"],
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
        },
        "Outputs": {"LogGroupName": {"Value": {"Ref": "LogGroup"}}},
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
