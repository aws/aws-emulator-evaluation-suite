"""cfn-stack-update-add-bedrock-agent-permission-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-add-bedrock-agent-permission-positive"
GROUP = "deployment-order"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update that adds bedrock:ListSessions to a Lambda's execution role turns its
    AccessDeniedException from bedrock-agent-runtime into a success."""
    template_before = _stack_template(include_s3vectors=True, include_bedrock=False)
    stack = _deploy_cfn(ctx, template_before, timeout_s=180)
    function_name = stack["outputs"]["FunctionName"]

    before = _poll_until(
        lambda: _invoke_and_parse(ctx, function_name),
        lambda r: r["s3vectors"]["ok"],
        timeout_s=60,
        interval_s=5.0,
        description="initial role permissions to become effective",
    )
    assert before["bedrock"]["ok"] is False, (
        f"expected bedrock-agent-runtime call to be denied before the permission was granted, "
        f"got {before['bedrock']!r}"
    )
    assert before["bedrock"]["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException before the permission was granted, "
        f"got error_code={before['bedrock'].get('error_code')!r}"
    )

    template_after = _stack_template(include_s3vectors=True, include_bedrock=True)
    _update_stack_and_wait(ctx, stack["stack_name"], template_after)

    after = _poll_until(
        lambda: _invoke_and_parse(ctx, function_name),
        lambda r: r["bedrock"]["ok"],
        timeout_s=60,
        interval_s=5.0,
        description="added bedrock-agent-runtime permission to become effective",
    )
    assert after["bedrock"]["ok"] is True, (
        f"expected bedrock-agent-runtime call to succeed after the stack update granted the "
        f"permission, got {after['bedrock']!r}"
    )
    assert isinstance(after["bedrock"]["count"], int), (
        f"expected an integer session count from list_sessions, got {after['bedrock']!r}"
    )
    assert after["s3vectors"]["ok"] is True, (
        f"expected the pre-existing s3vectors permission to still work after the stack update "
        f"added the bedrock permission, got {after['s3vectors']!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER_CODE = """import boto3


def handler(event, context):
    result = {}
    try:
        s3v = boto3.client("s3vectors")
        resp = s3v.list_vector_buckets()
        result["s3vectors"] = {"ok": True, "count": len(resp.get("vectorBuckets", []))}
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        result["s3vectors"] = {"ok": False, "error_code": code}
    try:
        bar = boto3.client("bedrock-agent-runtime")
        resp = bar.list_sessions()
        result["bedrock"] = {"ok": True, "count": len(resp.get("sessionSummaries", []))}
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        result["bedrock"] = {"ok": False, "error_code": code}
    return result
"""


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
        # DescribeStacks answers ValidationError "... does not exist" once the stack is gone.
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return "GONE"
            raise
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} is DELETE_FAILED")
        return status

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
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


def _update_stack_and_wait(
    ctx, stack_name: str, template_body: str, *, capabilities=None, timeout_s: float = 300.0
) -> None:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )

    def _status():
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]

    _poll_until(
        _status,
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"update stack {stack_name}",
    )
    status = _status()
    if status != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update on {stack_name} ended in {status}")


def _stack_template(*, include_s3vectors: bool, include_bedrock: bool) -> str:
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    if include_s3vectors:
        statements.append(
            {"Effect": "Allow", "Action": "s3vectors:ListVectorBuckets", "Resource": "*"}
        )
    if include_bedrock:
        statements.append(
            {"Effect": "Allow", "Action": "bedrock:ListSessions", "Resource": "*"}
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
                    "Policies": [
                        {
                            "PolicyName": "data-plane",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": statements,
                            },
                        }
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 15,
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
        },
        "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
    }
    return json.dumps(template)


def _invoke_and_parse(ctx, function_name: str) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps({}).encode("utf-8"))
    payload = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation for {function_name} errored: {payload}")
    return payload


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
