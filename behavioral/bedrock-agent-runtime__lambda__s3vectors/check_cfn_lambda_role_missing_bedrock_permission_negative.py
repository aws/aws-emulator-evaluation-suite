"""cfn-lambda-role-missing-bedrock-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-lambda-role-missing-bedrock-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_AGENT_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("bedrock-agent-runtime")
    try:
        resp = client.invoke_agent(
            agentId="AAAAAAAAAA",
            agentAliasId="BBBBBBBBBB",
            sessionId="sim2real-check-session-002",
            inputText="hello",
        )
        for evt in resp.get("completion", []):
            for key, value in evt.items():
                if key.lower().endswith("exception"):
                    return {"errorCode": key, "errorMessage": (value or {}).get("message")}
    except ClientError as e:
        err = e.response.get("Error", {})
        return {"errorCode": err.get("Code"), "errorMessage": err.get("Message")}
    return {"errorCode": None, "errorMessage": None}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack Lambda whose role lacks bedrock:InvokeAgent gets AccessDeniedException for a nonexistent
    agent, while a same-stack role with the permission gets ResourceNotFoundException for it."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    agent_alias_resource = f"arn:aws:bedrock:{region}:{account}:agent-alias/*"

    template = _template(agent_alias_resource)
    result = _deploy_cfn(ctx, template, teardown_deadline)
    denied_fn = result["outputs"]["DeniedFunctionName"]
    allowed_fn = result["outputs"]["AllowedFunctionName"]
    _wait_function_active(ctx, denied_fn)
    _wait_function_active(ctx, allowed_fn)

    denied_payload = _invoke_json(ctx, denied_fn)
    assert _normalize(denied_payload["errorCode"]) == "AccessDeniedException", denied_payload

    allowed_payload = _invoke_json(ctx, allowed_fn)
    assert (
        _normalize(allowed_payload["errorCode"]) == "ResourceNotFoundException"
    ), allowed_payload
    assert allowed_payload["errorMessage"] == (
        "Failed to retrieve resource because it doesn't exist. "
        "Retry the request with a different resource identifier."
    ), f"unexpected ResourceNotFoundException message {allowed_payload!r}"


def _template(agent_alias_resource: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "DeniedRole": {
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
                "DeniedFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["DeniedRole", "Arn"]},
                        "Timeout": 30,
                        "Code": {"ZipFile": _AGENT_CODE},
                    },
                },
                "AllowedRole": {
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
                        "Policies": [
                            {
                                "PolicyName": "AllowInvokeAgent",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "bedrock:InvokeAgent",
                                            "Resource": agent_alias_resource,
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "AllowedFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["AllowedRole", "Arn"]},
                        "Timeout": 30,
                        "Code": {"ZipFile": _AGENT_CODE},
                    },
                },
            },
            "Outputs": {
                "DeniedFunctionName": {"Value": {"Ref": "DeniedFn"}},
                "AllowedFunctionName": {"Value": {"Ref": "AllowedFn"}},
            },
        }
    )


def _normalize(code: str | None) -> str | None:
    if not code:
        return code
    return code[0].upper() + code[1:]


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


#: The suite's cleanup budget; the stack teardowns of one run share one deadline inside it.
_CLEANUP_BUDGET_S = 900.0


def _delete_stack_and_wait(ctx, stack_name: str, teardown_deadline) -> None:
    """Delete the stack and poll every 2 s until it is gone, to the run's cleanup deadline;
    DELETE_FAILED raises at once."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_BUDGET_S)
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} at the cleanup deadline")
        time.sleep(2)


def _deploy_cfn(
    ctx,
    template,
    teardown_deadline,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
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


def _wait_function_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"lambda {function_name} Active",
    )
    if state != "Active":
        raise AssertionError(f"function {function_name} ended in state {state}")


def _invoke_json(ctx, function_name: str, payload: dict | None = None) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    assert resp["StatusCode"] == 200, resp
    body = resp["Payload"].read()
    if "FunctionError" in resp:
        raise AssertionError(f"function error: {body!r}")
    return json.loads(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
