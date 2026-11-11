"""deploy-cfn-missing-secretsmanager-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-missing-secretsmanager-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


def _template(fn_code: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AllowSecretsAccess": {"Type": "String", "AllowedValues": ["true", "false"]}
        },
        "Conditions": {"GrantSecretsPolicy": {"Fn::Equals": [{"Ref": "AllowSecretsAccess"}, "true"]}},
        "Resources": {
            "Secret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"SecretString": "top-secret-value"},
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "SecretsPolicy": {
                "Type": "AWS::IAM::Policy",
                "Condition": "GrantSecretsPolicy",
                "Properties": {
                    "PolicyName": "secrets-access",
                    "Roles": [{"Ref": "ExecRole"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": {"Ref": "Secret"},
                            }
                        ],
                    },
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 10,
                    "Environment": {"Variables": {"SECRET_ARN": {"Ref": "Secret"}}},
                    "Code": {"ZipFile": fn_code},
                },
            },
        },
        "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
    }


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function in a stack whose role has no secretsmanager:GetSecretValue statement fails to read the secret
    with AccessDeniedException, while the same stack with that one statement returns "top-secret-value".
    """
    code = (
        "import json\n"
        "import os\n\n"
        "import boto3\n\n\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    try:\n"
        "        val = sm.get_secret_value(SecretId=os.environ['SECRET_ARN'])['SecretString']\n"
        "        return {'ok': True, 'secret': val}\n"
        "    except Exception as exc:\n"
        "        code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)\n"
        "        return {'ok': False, 'error_code': code}\n"
    )
    lam = ctx.client("lambda")

    # --- negative: policy statement withheld ---
    denied = _deploy_cfn(ctx, json.dumps(_template(code)), parameters={"AllowSecretsAccess": "false"})
    denied_fn = denied["outputs"]["FunctionName"]

    def _invoke_denied() -> dict[str, Any] | None:
        try:
            resp = lam.invoke(FunctionName=denied_fn, Payload=b"{}")
            return json.loads(resp["Payload"].read())
        except ClientError:
            return None

    denied_payload = _poll_until(
        _invoke_denied,
        lambda p: isinstance(p, dict) and p.get("ok") is False,
        timeout_s=90.0,
        interval_s=3.0,
        description="lambda invoke completes and reports secret retrieval denied",
    )
    assert denied_payload["ok"] is False, f"expected secret retrieval to fail, got {denied_payload!r}"
    assert denied_payload["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {denied_payload['error_code']!r}"
    )

    # --- positive control: identical stack, policy statement present ---
    allowed = _deploy_cfn(ctx, json.dumps(_template(code)), parameters={"AllowSecretsAccess": "true"})
    allowed_fn = allowed["outputs"]["FunctionName"]

    def _invoke_allowed() -> dict[str, Any] | None:
        try:
            resp = lam.invoke(FunctionName=allowed_fn, Payload=b"{}")
            return json.loads(resp["Payload"].read())
        except ClientError:
            return None

    allowed_payload = _poll_until(
        _invoke_allowed,
        lambda p: isinstance(p, dict) and p.get("ok") is True,
        timeout_s=90.0,
        interval_s=3.0,
        description="lambda invoke retrieves the secret once the policy statement is granted",
    )
    assert allowed_payload["ok"] is True, f"expected secret retrieval to succeed, got {allowed_payload!r}"
    assert allowed_payload["secret"] == "top-secret-value", (
        f"expected the deployed secret value, got {allowed_payload.get('secret')!r}"
    )


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
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

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
