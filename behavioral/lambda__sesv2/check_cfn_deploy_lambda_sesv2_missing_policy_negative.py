"""cfn-deploy-lambda-sesv2-missing-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-missing-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:SendEmail gets AccessDeniedException and no message id, while a
    function in the same stack whose role grants it reaches SES's own MessageRejected for the
    unverified sender."""
    from_addr = f"{ctx.unique_name('sim2real-xsvc-from-')}@example.com"
    to_addr = f"{ctx.unique_name('sim2real-xsvc-to-')}@example.com"
    denied_fn = ctx.unique_name("sim2real-xsvc-denied-")
    allowed_fn = ctx.unique_name("sim2real-xsvc-allowed-")

    def _role(logical_id: str, grant_send: bool) -> dict[str, Any]:
        statements = [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ]
        if grant_send:
            statements.append({"Effect": "Allow", "Action": "ses:SendEmail", "Resource": "*"})
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
                "Policies": [{"PolicyName": "inline", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}],
            },
        }

    def _fn(logical_id: str, name: str, role_logical_id: str) -> dict[str, Any]:
        return {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Timeout": 15,
                "Role": {"Fn::GetAtt": [role_logical_id, "Arn"]},
                "Code": {"ZipFile": _LAMBDA_CODE_SEND},
            },
        }

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DeniedRole": _role("DeniedRole", grant_send=False),
            "AllowedRole": _role("AllowedRole", grant_send=True),
            "DeniedFn": _fn("DeniedFn", denied_fn, "DeniedRole"),
            "AllowedFn": _fn("AllowedFn", allowed_fn, "AllowedRole"),
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    denied_body = _invoke_json(ctx, denied_fn, {"from": from_addr, "to": to_addr})
    assert denied_body["ok"] is False, f"expected the send to be denied, got ok=True: {denied_body}"
    assert denied_body["errorCode"] == "AccessDeniedException", (
        f"expected AccessDeniedException (no ses:SendEmail statement), got {denied_body['errorCode']!r}: {denied_body}"
    )
    assert "messageId" not in denied_body, (
        f"the effect (a sent message) must never happen when IAM denies the call: {denied_body}"
    )

    # Positive control, in the SAME file: identical code/payload, only the role's policy differs.
    allowed_body = _invoke_json(ctx, allowed_fn, {"from": from_addr, "to": to_addr})
    assert allowed_body["ok"] is False, (
        f"expected rejection for an unverified sender, got ok=True: {allowed_body}"
    )
    assert allowed_body["errorCode"] == "MessageRejected", (
        f"expected MessageRejected (reached SES, unverified sender), got {allowed_body['errorCode']!r}: {allowed_body}"
    )
    assert allowed_body["errorCode"] != "AccessDeniedException", (
        f"granting ses:SendEmail must clear the IAM denial; got AccessDeniedException again: {allowed_body}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_LAMBDA_CODE_SEND = '''
import os
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.send_email(
            FromEmailAddress=event.get("from") or os.environ.get("FROM_ADDRESS", ""),
            Destination={"ToAddresses": [event.get("to") or os.environ.get("TO_ADDRESS", "")]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real-behavioral-test"},
                    "Body": {"Text": {"Data": "hello from sim2real"}},
                }
            },
        )
        return {"ok": True, "messageId": resp["MessageId"]}
    except ClientError as e:
        return {"ok": False, "errorCode": e.response["Error"]["Code"], "message": str(e)}
'''


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


def _invoke_json(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")

    def _invoke_once():
        return lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())

    resp = _poll_until(
        _invoke_once,
        lambda r: r.get("StatusCode") == 200 and not str(r.get("FunctionError", "")).startswith("Unhandled"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"successful invoke of {function_name}",
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"Lambda invocation failed ({resp['FunctionError']}): {body}")
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
