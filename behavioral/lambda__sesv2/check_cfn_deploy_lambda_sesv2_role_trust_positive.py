"""cfn-deploy-lambda-sesv2-role-trust-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-role-trust-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Lambda execution role trusting lambda.amazonaws.com and granting
    ses:SendEmail lets the deployed function actually reach the SESv2 SendEmail business
    logic (not blocked by IAM) on invocation."""
    from_address = f"{ctx.unique_name('sim2real-ses-')}@example.com"
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")

    template = json.dumps(
        {
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
                                "PolicyName": "SesSendEmailAndLogs",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["ses:SendEmail", "ses:SendRawEmail"],
                                            "Resource": "*",
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "logs:CreateLogGroup",
                                                "logs:CreateLogStream",
                                                "logs:PutLogEvents",
                                            ],
                                            "Resource": "*",
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "SendFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": fn_name,
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Timeout": 20,
                        "Environment": {"Variables": {"FROM_ADDRESS": from_address}},
                        "Code": {"ZipFile": _SEND_EMAIL_LAMBDA_CODE},
                    },
                },
            },
            "Outputs": {"FunctionName": {"Value": {"Ref": "SendFn"}}},
        }
    )

    deployed = _deploy_cfn(ctx, template, timeout_s=420.0)
    function_name = deployed["outputs"]["FunctionName"]
    assert function_name == fn_name

    lam = ctx.client("lambda")

    def _invoke_once():
        return lam.invoke(FunctionName=function_name, Payload=b"{}")

    # A freshly-created function/role may not have propagated through IAM yet; poll the
    # invocation itself rather than sleeping a fixed duration.
    resp = _poll_until(
        _invoke_once,
        lambda r: r.get("StatusCode") == 200 and not str(r.get("FunctionError", "")).startswith("Unhandled"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"successful invoke of {function_name}",
    )
    assert "FunctionError" not in resp, resp.get("FunctionError")
    payload = json.loads(resp["Payload"].read())

    # The role was correctly trusted and permissioned, so the call reached SESv2's business
    # logic layer (not blocked by IAM) and failed only because the from-address is a fresh,
    # never-verified identity -- a deterministic SES-level rejection, not an IAM one.
    assert payload["outcome"] == "error", payload
    assert payload["errorCode"] == "MessageRejected", payload
    expected_rejection = (
        "Email address is not verified. The following identities failed "
        f"the check in region {ctx.region.upper()}: {from_address}"
    )
    assert payload["errorMessage"] == expected_rejection, f"{payload!r} != {expected_rejection!r}"


_SEND_EMAIL_LAMBDA_CODE = """
import json
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    from_address = os.environ["FROM_ADDRESS"]
    try:
        resp = client.send_email(
            FromEmailAddress=from_address,
            Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real test"},
                    "Body": {"Text": {"Data": "sim2real test body"}},
                }
            },
        )
        return {"outcome": "sent", "messageId": resp.get("MessageId")}
    except ClientError as e:
        return {
            "outcome": "error",
            "errorCode": e.response["Error"]["Code"],
            "errorMessage": e.response["Error"]["Message"],
        }
""".strip()


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
