"""cfn-deploy-lambda-sesv2-identity-resource-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-identity-resource-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda given a stack's email identity name by Ref calls PutEmailIdentityDkimAttributes on
    exactly that identity, which stays attached to the stack's configuration set with DKIM
    signing enabled."""
    config_set_name = ctx.unique_name("sim2real-xsvc-cfgset-")
    identity_domain = f"{ctx.unique_name('sim2real-xsvc-id-')}.example.com"
    fn_name = ctx.unique_name("sim2real-xsvc-dkimfn-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ConfigSet": {
                "Type": "AWS::SES::ConfigurationSet",
                "Properties": {"Name": config_set_name, "Tags": _xsvc_tags_kv()},
            },
            "Identity": {
                "Type": "AWS::SES::EmailIdentity",
                "Properties": {
                    "EmailIdentity": identity_domain,
                    "ConfigurationSetAttributes": {"ConfigurationSetName": {"Ref": "ConfigSet"}},
                    "Tags": _xsvc_tags_kv(),
                },
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Tags": _xsvc_tags_kv(),
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
                                        "Action": [
                                            "ses:PutEmailIdentityDkimAttributes",
                                            "ses:GetEmailIdentity",
                                        ],
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "DkimFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Environment": {"Variables": {"IDENTITY_NAME": {"Ref": "Identity"}}},
                    "Code": {"ZipFile": _LAMBDA_CODE_DKIM},
                    "Tags": _xsvc_tags_kv(),
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))
    ses = ctx.client("sesv2")
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=identity_domain))

    body = _invoke_json(ctx, fn_name, {})
    assert body["ok"] is True, f"expected the DKIM call to succeed, got {body}"
    assert body["identity"] == identity_domain, (
        f"expected the function to report back the identity it was given ({identity_domain}), got {body}"
    )

    # Confirm the association the template asked for was actually created, and the toggle we
    # just made through Lambda really landed on the identity SES holds.
    identity = ses.get_email_identity(EmailIdentity=identity_domain)
    assert identity["ConfigurationSetName"] == config_set_name, (
        f"expected identity {identity_domain} to be attached to config set {config_set_name}, "
        f"got {identity.get('ConfigurationSetName')!r}"
    )
    assert identity["DkimAttributes"]["SigningEnabled"] is True, (
        f"expected DKIM signing to be enabled on {identity_domain} after the Lambda's "
        f"PutEmailIdentityDkimAttributes call, got {identity['DkimAttributes']}"
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
