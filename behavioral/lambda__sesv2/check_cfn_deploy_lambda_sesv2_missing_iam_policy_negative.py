"""cfn-deploy-lambda-sesv2-missing-iam-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-missing-iam-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role with no SES permission gets AccessDeniedException from SendEmail, while a
    sibling role with ses:SendEmail reaches SES and gets MessageRejected, so the IAM policy is
    the only boundary."""
    from_address = f"{ctx.unique_name('sim2real-ses-')}@example.com"

    no_perm_stack = _deploy_stack(ctx, from_address=from_address, grant_ses=False)
    lam = ctx.client("lambda")

    resp = lam.invoke(FunctionName=no_perm_stack["outputs"]["FunctionName"], Payload=b"{}")
    assert "FunctionError" not in resp, resp.get("FunctionError")
    payload = json.loads(resp["Payload"].read())

    # blocked at the IAM layer -- never reached SES's business logic
    assert payload["outcome"] == "error", payload
    assert payload["errorCode"] == "AccessDeniedException", payload
    # the specific SES-level rejection ("MessageRejected") never happens here: SES never saw it
    assert payload["errorCode"] != "MessageRejected"

    # --- positive control: identical stack, but the role is granted ses:SendEmail ---
    with_perm_stack = _deploy_stack(ctx, from_address=from_address, grant_ses=True)
    resp2 = lam.invoke(FunctionName=with_perm_stack["outputs"]["FunctionName"], Payload=b"{}")
    assert "FunctionError" not in resp2, resp2.get("FunctionError")
    payload2 = json.loads(resp2["Payload"].read())
    assert payload2["outcome"] == "error", payload2
    assert payload2["errorCode"] == "MessageRejected", payload2
    expected_rejection = (
        "Email address is not verified. The following identities failed "
        f"the check in region {ctx.region.upper()}: {from_address}"
    )
    assert payload2["errorMessage"] == expected_rejection, f"{payload2!r} != {expected_rejection!r}"


def _deploy_stack(ctx, *, from_address: str, grant_ses: bool) -> dict[str, Any]:
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    if grant_ses:
        statements.append(
            {"Effect": "Allow", "Action": ["ses:SendEmail", "ses:SendRawEmail"], "Resource": "*"}
        )
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
                        "Policies": [{"PolicyName": "LambdaLogsOnly", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}],
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
    return _deploy_cfn(ctx, template, timeout_s=300.0)


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
