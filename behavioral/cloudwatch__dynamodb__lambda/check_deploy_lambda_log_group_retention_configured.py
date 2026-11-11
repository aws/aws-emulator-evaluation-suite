"""deploy-lambda-log-group-retention-configured."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-log-group-retention-configured"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed Lambda function's associated CloudWatch Logs log group has the retention
    policy declared in the template applied — and the function actually writes into that same
    log group on invocation."""
    function_name = _xname(ctx, "fn")
    log_group_name = f"/aws/lambda/{function_name}"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "logs",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 7,
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": "LogGroup",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": "def handler(event, context):\n    return {'ok': True}\n"},
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    logs = ctx.client("logs")
    lam = ctx.client("lambda")

    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    matches = [g for g in groups if g["logGroupName"] == log_group_name]
    assert len(matches) == 1, f"expected exactly one log group {log_group_name}, got {matches}"
    assert matches[0].get("retentionInDays") == 7, (
        f"expected retentionInDays=7 on {log_group_name}, got {matches[0].get('retentionInDays')!r}"
    )

    # The retention setting must apply to the SAME log group the function actually writes to.
    invoke_resp = lam.invoke(FunctionName=function_name, InvocationType="RequestResponse", Payload=b"{}")
    assert invoke_resp.get("FunctionError") is None, f"unexpected invoke error: {invoke_resp}"
    events = _poll_until(
        lambda: logs.filter_log_events(logGroupName=log_group_name).get("events", []),
        lambda evs: len(evs) > 0,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"log events appearing in {log_group_name}",
    )
    assert len(events) > 0, f"expected at least one log event in {log_group_name}, got none"

    # Lambda's automatic log-group-on-first-use path must not clobber the CFN-managed retention
    # that was already in place before this, the function's first, invocation.
    after = [
        g
        for g in logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
        if g["logGroupName"] == log_group_name
    ]
    assert len(after) == 1, f"expected exactly one log group {log_group_name} after invoke, got {after}"
    assert after[0].get("retentionInDays") == 7, (
        f"retention on {log_group_name} changed after invoke: expected 7, got {after[0].get('retentionInDays')!r}"
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
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
