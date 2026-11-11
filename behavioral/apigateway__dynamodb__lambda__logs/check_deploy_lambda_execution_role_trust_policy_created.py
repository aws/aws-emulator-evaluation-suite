"""deploy-lambda-execution-role-trust-policy-created."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-execution-role-trust-policy-created"
GROUP = "deployment-wiring"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed Lambda execution role must carry an AssumeRolePolicyDocument that trusts
    lambda.amazonaws.com — checked against the actual IAM role fetched post-deploy, not the
    template we sent."""
    function_name = _xname(ctx, "fn")
    role_name = _xname(ctx, "role")
    template = _build_template(function_name=function_name, role_name=role_name)
    stack = _deploy_cfn(ctx, template)
    role_arn = stack["outputs"]["RoleArn"]
    assert role_arn.split("/")[-1] == role_name, (
        f"expected RoleArn output {role_arn!r} to name role {role_name!r}"
    )

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly 1 trust statement, got {statements!r}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected Effect=Allow, got {stmt['Effect']!r}"
    assert stmt["Action"] == "sts:AssumeRole", f"expected Action=sts:AssumeRole, got {stmt['Action']!r}"
    principal = stmt["Principal"]
    service = principal["Service"]
    if isinstance(service, list):
        assert "lambda.amazonaws.com" in service, (
            f"expected lambda.amazonaws.com among trusted services, got {service!r}"
        )
    else:
        assert service == "lambda.amazonaws.com", (
            f"expected trusted service lambda.amazonaws.com, got {service!r}"
        )

    stack_name = stack["stack_name"]
    _delete_stack_and_wait(ctx, stack_name)
    try:
        iam.get_role(RoleName=role_name)
        raise AssertionError(f"expected role {role_name!r} to be gone after stack {stack_name!r} deletion")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "NoSuchEntity", (
            f"expected NoSuchEntity reading role {role_name!r} after stack deletion, got {code!r}"
        )
        message = e.response["Error"].get("Message")
        assert message == f"The role with name {role_name} cannot be found.", message


# ===== helpers =====
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
            # DescribeStacks on a stack that no longer exists: ValidationError "... does not exist".
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "GONE"
            raise

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


_HANDLER_CODE = """def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
"""


def _build_template(*, function_name: str, role_name: str) -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": "ExecRole",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Function", "Arn"]}},
        },
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
