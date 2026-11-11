"""cfn-stack-update-lambda-sesv2-identity-env-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-lambda-sesv2-identity-env-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update that changes the sender identity in the Lambda's environment makes the next
    invocation's SendEmail use the new identity: SES's MessageRejected names it and not the old
    one."""
    identity_v1 = f"{ctx.unique_name('sim2real-ses-v1-')}@example.com"
    identity_v2 = f"{ctx.unique_name('sim2real-ses-v2-')}@example.com"
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")

    stack = _deploy_cfn(ctx, _template(fn_name, identity_v1), timeout_s=300.0)
    lam = ctx.client("lambda")

    resp1 = lam.invoke(FunctionName=stack["outputs"]["FunctionName"], Payload=b"{}")
    assert "FunctionError" not in resp1, resp1.get("FunctionError")
    payload1 = json.loads(resp1["Payload"].read())
    assert payload1["outcome"] == "error" and payload1["errorCode"] == "MessageRejected", payload1
    assert identity_v1 in payload1["errorMessage"], payload1
    assert identity_v2 not in payload1["errorMessage"], payload1

    # update the stack: only the Lambda's FROM_ADDRESS env var changes
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack["stack_name"],
        TemplateBody=_template(fn_name, identity_v2),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack["stack_name"])["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"CFN stack update {stack['stack_name']}",
    )
    final_status = cfn.describe_stacks(StackName=stack["stack_name"])["Stacks"][0]["StackStatus"]
    assert final_status == "UPDATE_COMPLETE", final_status

    resp2 = lam.invoke(FunctionName=stack["outputs"]["FunctionName"], Payload=b"{}")
    assert "FunctionError" not in resp2, resp2.get("FunctionError")
    payload2 = json.loads(resp2["Payload"].read())
    assert payload2["outcome"] == "error" and payload2["errorCode"] == "MessageRejected", payload2
    assert identity_v2 in payload2["errorMessage"], payload2
    assert identity_v1 not in payload2["errorMessage"], payload2


def _template(fn_name: str, from_address: str) -> str:
    return json.dumps(
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
