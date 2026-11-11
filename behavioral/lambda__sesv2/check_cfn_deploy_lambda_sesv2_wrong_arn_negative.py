"""cfn-deploy-lambda-sesv2-wrong-arn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-wrong-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack whose Lambda names a never-created SES identity deploys, but the function's call on
    it fails with BadRequestException and SES's exact message, while a sibling function wired to the
    stack's real identity succeeds."""
    real_domain = f"{ctx.unique_name('sim2real-xsvc-real-')}.example.com"
    fake_domain = f"{ctx.unique_name('sim2real-xsvc-fake-')}.invalid.example"
    valid_fn = ctx.unique_name("sim2real-xsvc-validfn-")
    invalid_fn = ctx.unique_name("sim2real-xsvc-invalidfn-")

    def _fn(name: str, identity_env: str) -> dict[str, Any]:
        return {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Timeout": 15,
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Environment": {"Variables": {"IDENTITY_NAME": identity_env}},
                "Code": {"ZipFile": _LAMBDA_CODE_DKIM},
            },
        }

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RealIdentity": {
                "Type": "AWS::SES::EmailIdentity",
                "Properties": {"EmailIdentity": real_domain},
            },
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
                            "PolicyName": "sesv2-dkim",
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
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "ses:PutEmailIdentityDkimAttributes",
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "ValidFn": _fn(valid_fn, {"Ref": "RealIdentity"}),
            "InvalidFn": _fn(invalid_fn, fake_domain),
        },
    }

    _deploy_cfn(ctx, json.dumps(template))
    ses = ctx.client("sesv2")
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=real_domain))

    invalid_body = _invoke_json(ctx, invalid_fn, {})
    assert invalid_body["ok"] is False, f"expected failure against the fake identity, got {invalid_body}"
    assert invalid_body["errorCode"] == "BadRequestException", (
        f"expected BadRequestException against the fake identity, got {invalid_body}"
    )
    expected_message = (
        "An error occurred (BadRequestException) when calling the PutEmailIdentityDkimAttributes "
        f"operation: Domain {fake_domain} is not verified for DKIM signing."
    )
    assert invalid_body["message"] == expected_message, (
        f"expected SES's exact not-found message {expected_message!r}, got {invalid_body}"
    )

    # Positive control, in the SAME file: identical code/permissions, pointed at the identity the
    # stack actually created.
    valid_body = _invoke_json(ctx, valid_fn, {})
    assert valid_body["ok"] is True, f"expected success against the real identity, got {valid_body}"
    assert valid_body["identity"] == real_domain, (
        f"expected the successful call to report the real identity {real_domain!r}, got {valid_body}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_LAMBDA_CODE_DKIM = '''
import os
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("sesv2")
    identity = event.get("identity") or os.environ.get("IDENTITY_NAME", "")
    try:
        client.put_email_identity_dkim_attributes(EmailIdentity=identity, SigningEnabled=True)
        return {"ok": True, "identity": identity}
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
