"""cfn-deploy-lambda-sesv2-env-configset-arn-resolution."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-env-configset-arn-resolution"
GROUP = "arn-resolution"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A configuration set Ref passed as a Lambda environment variable resolves to the deployed
    set's exact name, and the function's GetConfigurationSet call with it returns that same set."""
    config_set_name = ctx.unique_name("sim2real-xsvc-cfgset-")
    fn_name = ctx.unique_name("sim2real-xsvc-cfgfn-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ConfigSet": {
                "Type": "AWS::SES::ConfigurationSet",
                "Properties": {"Name": config_set_name},
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
                            "PolicyName": "sesv2-getconfigset",
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
                                        "Action": "ses:GetConfigurationSet",
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "ConfigSetFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Environment": {"Variables": {"CONFIG_SET_NAME": {"Ref": "ConfigSet"}}},
                    "Code": {"ZipFile": _LAMBDA_CODE_CONFIGSET},
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    body = _invoke_json(ctx, fn_name, {})
    assert body["ok"] is True, f"expected GetConfigurationSet to succeed, got {body}"
    assert body["name"] == config_set_name, (
        f"expected the Lambda's GetConfigurationSet (using the {{Ref: ConfigSet}}-resolved env "
        f"var) to see the exact name CFN deployed {config_set_name!r}, got {body['name']!r}"
    )

    # Cross-check directly against the control plane: the name the Lambda saw via the resolved
    # Ref must be the SAME configuration set the stack deployed, not a lookalike.
    actual = ctx.client("sesv2").get_configuration_set(ConfigurationSetName=config_set_name)
    assert actual["ConfigurationSetName"] == body["name"], (
        f"expected the independently-read configuration set name {actual['ConfigurationSetName']!r} "
        f"to match the name the Lambda saw via the resolved Ref {body['name']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_LAMBDA_CODE_CONFIGSET = '''
import os
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("sesv2")
    name = os.environ.get("CONFIG_SET_NAME", "")
    try:
        resp = client.get_configuration_set(ConfigurationSetName=name)
        return {"ok": True, "name": resp["ConfigurationSetName"]}
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
