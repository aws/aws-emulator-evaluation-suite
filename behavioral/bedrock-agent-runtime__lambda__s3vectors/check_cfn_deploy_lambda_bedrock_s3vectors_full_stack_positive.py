"""cfn-deploy-lambda-bedrock-s3vectors-full-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-bedrock-s3vectors-full-stack-positive"
GROUP = "deployment-order"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A full CFN stack (Lambda + execution role with s3vectors & bedrock-agent-runtime
    permissions) lets the deployed function call both services successfully end-to-end."""
    template = _stack_template(include_s3vectors=True, include_bedrock=True)
    stack = _deploy_cfn(ctx, template, timeout_s=180)
    function_name = stack["outputs"]["FunctionName"]

    # IAM role permission changes/propagation for a brand-new role can lag a few seconds behind
    # CREATE_COMPLETE, so poll for the effect rather than asserting immediately.
    result = _poll_until(
        lambda: _invoke_and_parse(ctx, function_name),
        lambda r: r["s3vectors"]["ok"] and r["bedrock"]["ok"],
        timeout_s=60,
        interval_s=5.0,
        description="deployed Lambda role IAM permissions to become effective",
    )
    assert result["s3vectors"]["ok"] is True, (
        f"expected the deployed role's s3vectors:ListVectorBuckets call to succeed, got {result['s3vectors']!r}"
    )
    assert isinstance(result["s3vectors"]["count"], int), (
        f"expected an int vector-bucket count, got {result['s3vectors']['count']!r}"
    )
    assert result["bedrock"]["ok"] is True, (
        f"expected the deployed role's bedrock:ListSessions call to succeed, got {result['bedrock']!r}"
    )
    assert isinstance(result["bedrock"]["count"], int), (
        f"expected an int session count, got {result['bedrock']['count']!r}"
    )


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
