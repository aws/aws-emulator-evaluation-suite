"""cfn-iam-role-trusts-lambda-service-principal."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-trusts-lambda-service-principal"
GROUP = "iam-trust"
SERVICES = ["events", "lambda", "sqs"]

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "FunctionNameParam": {"Type": "String"},
        "RoleNameParam": {"Type": "String"},
    },
    "Resources": {
        "ExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "RoleNameParam"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "ManagedPolicyArns": [
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                ],
            },
        },
        "Fn": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": {"Ref": "FunctionNameParam"},
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Timeout": 10,
                "Code": {
                    "ZipFile": (
                        "import boto3\n"
                        "def handler(event, context):\n"
                        "    ident = boto3.client('sts').get_caller_identity()\n"
                        "    return {'arn': ident['Arn']}\n"
                    )
                },
            },
        },
    },
    "Outputs": {
        "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
        "RoleName": {"Value": {"Ref": "ExecRole"}},
        "FunctionArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
    },
})


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN role trusting lambda.amazonaws.com is really assumed at invoke time: the
    function's own runtime credentials (via sts:GetCallerIdentity) resolve to that role."""
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "lambda-trust-role")
    function_name = _xname(ctx, "lambda-trust-fn")

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"FunctionNameParam": function_name, "RoleNameParam": role_name},
    )
    role_arn = result["outputs"]["RoleArn"]
    assert role_arn.endswith(f":role/{role_name}"), (
        f"expected role ARN ending :role/{role_name}, got {role_arn}"
    )

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3.0,
        description=f"function {function_name} Active",
    )

    invoke = lam.invoke(FunctionName=function_name, InvocationType="RequestResponse")
    assert invoke.get("FunctionError") is None, f"invoke failed: {invoke.get('FunctionError')}"
    payload = json.loads(invoke["Payload"].read())
    # The assumed-role ARN format is arn:aws:sts::<acct>:assumed-role/<RoleName>/<SessionName>.
    # If lambda.amazonaws.com could not assume ExecRole, invocation would never have reached
    # user code at all (Lambda validates the trust at CreateFunction / provisioning time).
    assert f"assumed-role/{role_name}/" in payload["arn"], payload


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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
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
