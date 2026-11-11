"""cfn-deploy-lambda-sesv2-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-stack-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack-deployed Lambda whose role grants ses:SendEmail passes IAM and reaches SES's own
    identity check, which rejects the unverified sender with MessageRejected 'not verified'."""
    stack = _deploy_cfn(ctx, _template(ses_actions=["ses:SendEmail"]))
    function_name = stack["outputs"]["FunctionName"]
    _wait_function_active(ctx, function_name)
    result = _invoke_and_get_result(ctx, function_name)
    assert result["ok"] is False, f"unexpected success payload: {result}"
    assert result["code"] == "MessageRejected", f"unexpected sesv2 error code: {result}"
    assert "not verified" in result["message"].lower(), (
        f"MessageRejected for a reason other than sender verification: {result}"
    )


_LAMBDA_CODE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.send_email(
            FromEmailAddress="sim2real-noreply@example.com",
            Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real"},
                    "Body": {"Text": {"Data": "sim2real"}},
                }
            },
        )
        return {"ok": True}
    except ClientError as exc:
        return {
            "ok": False,
            "code": exc.response["Error"]["Code"],
            "message": exc.response["Error"]["Message"],
        }
"""


def _role_resource(ses_actions: list[str]) -> dict[str, Any]:
    policies = []
    if ses_actions:
        policies.append(
            {
                "PolicyName": "ses-access",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ses_actions, "Resource": "*"}
                    ],
                },
            }
        )
    return {
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
            "Policies": policies,
        },
    }


def _function_resource(role_logical_id: str) -> dict[str, Any]:
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Role": {"Fn::GetAtt": [role_logical_id, "Arn"]},
            "Timeout": 15,
            "Code": {"ZipFile": _LAMBDA_CODE},
        },
    }


def _template(ses_actions: list[str]) -> str:
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": _role_resource(ses_actions),
            "Function": _function_resource("Role"),
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "Function"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    }
    return json.dumps(doc)


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
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

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


def _wait_function_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"function {function_name} Active",
    )


def _invoke_and_get_result(ctx, function_name: str, timeout_s: float = 60.0) -> dict[str, Any]:
    """Invoke and return the parsed JSON payload, retrying past IAM role-propagation lag."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
            payload = json.loads(resp["Payload"].read())
            if resp.get("FunctionError"):
                raise AssertionError(f"function {function_name} errored: {payload}")
            return payload
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"invoke of {function_name} never succeeded: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
