"""cfn-stack-update-lambda-sesv2-permission-add-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-lambda-sesv2-permission-add-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update that adds ses:SendEmail to the Lambda role, with the function code unchanged,
    turns its SendEmail AccessDeniedException into SES's own MessageRejected for the unverified
    sender."""
    from_addr = f"{ctx.unique_name('sim2real-xsvc-from-')}@example.com"
    to_addr = f"{ctx.unique_name('sim2real-xsvc-to-')}@example.com"
    fn_name = ctx.unique_name("sim2real-xsvc-updfn-")

    def _template(grant_send: bool) -> str:
        statements = [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ]
        if grant_send:
            statements.append({"Effect": "Allow", "Action": "ses:SendEmail", "Resource": "*"})
        doc = {
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
                            {"PolicyName": "inline", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}
                        ],
                    },
                },
                "SendFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": fn_name,
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Timeout": 15,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {"ZipFile": _LAMBDA_CODE_SEND},
                    },
                },
            },
        }
        return json.dumps(doc)

    deployed = _deploy_cfn(ctx, _template(grant_send=False))
    stack_name = deployed["stack_name"]

    before_sha = ctx.client("lambda").get_function(FunctionName=fn_name)["Configuration"]["CodeSha256"]

    denied_body = _invoke_json(ctx, fn_name, {"from": from_addr, "to": to_addr})
    assert denied_body["ok"] is False, f"expected the pre-grant invoke to fail, got {denied_body!r}"
    assert denied_body["errorCode"] == "AccessDeniedException", (
        f"expected AccessDeniedException before granting ses:SendEmail, got {denied_body!r}"
    )

    _update_stack_and_wait(ctx, stack_name, _template(grant_send=True))

    after_sha = ctx.client("lambda").get_function(FunctionName=fn_name)["Configuration"]["CodeSha256"]
    assert after_sha == before_sha, "function code was redeployed by the permission-only update"

    # IAM policy propagation to the role's assumed credentials is eventually consistent even after
    # the stack reports UPDATE_COMPLETE, so the AccessDeniedException can persist for a few seconds
    # past the update — poll for the specific error to clear rather than trusting a single invoke.
    allowed_body = _poll_until(
        lambda: _invoke_json(ctx, fn_name, {"from": from_addr, "to": to_addr}),
        lambda b: b.get("errorCode") != "AccessDeniedException",
        timeout_s=90.0,
        interval_s=5.0,
        description="invoke result to stop being AccessDeniedException after permission grant",
    )
    # still an unverified sender, but no longer blocked by IAM
    assert allowed_body["ok"] is False, f"expected the post-grant invoke to still fail, got {allowed_body!r}"
    assert allowed_body["errorCode"] == "MessageRejected", (
        f"expected MessageRejected (unverified sender) after granting ses:SendEmail, got {allowed_body!r}"
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


def _update_stack_and_wait(ctx, stack_name: str, template_body: str, *, capabilities=None, timeout_s=300.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update {stack_name} ended in {stack['StackStatus']}")


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
