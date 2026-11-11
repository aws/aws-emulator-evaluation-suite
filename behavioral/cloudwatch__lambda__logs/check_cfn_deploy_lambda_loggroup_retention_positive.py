"""cfn-deploy-lambda-loggroup-retention-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-loggroup-retention-positive"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A stack's explicit log group deploys with retention 7, and the retention stays 7 after
    the function's first invoke writes log events to it."""
    fn_name = _xname(ctx, "fn")
    log_group_name = f"/aws/lambda/{fn_name}"

    code = (
        "def handler(event, context):\n"
        "    print('sim2real-retention-check invoked')\n"
        "    return {'ok': True}\n"
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "AppLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 7,
                },
            },
            "AppFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["AppLogGroup"],
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": code},
                    "Timeout": 30,
                },
            },
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "AppFunction"}},
            "LogGroupName": {"Value": {"Ref": "AppLogGroup"}},
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    logs = ctx.client("logs")
    lam = ctx.client("lambda")

    def _describe_lg():
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        for g in resp.get("logGroups", []):
            if g["logGroupName"] == log_group_name:
                return g
        return None

    before = _poll_until(
        _describe_lg,
        lambda g: g is not None,
        timeout_s=60,
        interval_s=2.0,
        description=f"log group {log_group_name} to exist",
    )
    assert before["retentionInDays"] == 7, before

    invoke_resp = lam.invoke(
        FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}"
    )
    assert invoke_resp["StatusCode"] == 200, invoke_resp
    assert "FunctionError" not in invoke_resp, invoke_resp

    def _events():
        return logs.filter_log_events(logGroupName=log_group_name).get("events", [])

    events = _poll_until(
        _events,
        lambda evs: len(evs) >= 1,
        timeout_s=60,
        interval_s=3.0,
        description="log events to appear after invocation",
    )
    assert len(events) >= 1, events

    after = _describe_lg()
    assert after is not None and after["retentionInDays"] == 7, (
        f"retention must remain 7 after Lambda's first write to the pre-existing "
        f"CFN-managed log group, got {after}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


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
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
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
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
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
