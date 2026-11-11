"""cfn-lambda-role-trusts-lambda-service-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-role-trusts-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-created execution role whose AssumeRolePolicyDocument trusts lambda.amazonaws.com
    lets Lambda actually assume it and invoke the function end to end."""
    marker = ctx.unique_name("sim2real-trust-")
    result = _deploy_cfn(ctx, _template(marker))
    role_name = result["outputs"]["RoleName"]
    function_name = result["outputs"]["FunctionName"]

    iam = ctx.client("iam")
    trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly one trust statement, got {statements}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow"
    principal = stmt["Principal"]["Service"]
    if isinstance(principal, list):
        assert principal == ["lambda.amazonaws.com"]
    else:
        assert principal == "lambda.amazonaws.com"
    assert stmt["Action"] == "sts:AssumeRole"

    lam = ctx.client("lambda")

    def _invoke() -> dict[str, Any]:
        return lam.invoke(FunctionName=function_name, Payload=b"{}")

    # Right after CreateFunction, invoking can transiently fail while IAM/Lambda propagate the
    # trust relationship; poll for the eventual successful assumption + execution.
    resp = _poll_until(
        _invoke,
        lambda r: "FunctionError" not in r,
        timeout_s=60.0,
        interval_s=3.0,
        description="lambda invocation succeeds using the CFN-trusted role",
    )
    assert "FunctionError" not in resp, f"lambda invocation errored: {resp}"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"marker": marker}, f"unexpected payload: {payload}"

    # The delete is already registered via ctx.on_cleanup; prove it actually removes the role and
    # the function rather than merely being called, by deleting now and reading independently.
    _delete_stack_and_wait(ctx, result["stack_name"])
    role_code, role_message = _client_error(lambda: iam.get_role(RoleName=role_name))
    assert role_code == "NoSuchEntity", f"role should be gone after stack delete, got code={role_code}"
    expected_role_message = f"The role with name {role_name} cannot be found."
    assert role_message == expected_role_message, (
        f"expected message {expected_role_message!r}, got {role_message!r}"
    )
    function_code, function_message = _client_error(lambda: lam.get_function(FunctionName=function_name))
    assert function_code == "ResourceNotFoundException", (
        f"function should be gone after stack delete, got code={function_code}"
    )
    expected_function_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    )
    assert function_message == expected_function_message, (
        f"expected message {expected_function_message!r}, got {function_message!r}"
    )


def _template(marker: str) -> str:
    code = "import os\n" "def handler(event, context):\n" "    return {'marker': os.environ.get('MARKER', '')}\n"
    template = {
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
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": code},
                    "Environment": {"Variables": {"MARKER": marker}},
                },
            },
        },
        "Outputs": {
            "RoleName": {"Value": {"Ref": "ExecRole"}},
            "FunctionName": {"Value": {"Ref": "Fn"}},
        },
    }
    return json.dumps(template)


# ===== helpers =====

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _client_error(fn):
    """Call fn, which AWS must refuse, and return the (code, message) of its ClientError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
    template_body = template
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
        lambda s: (s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}),
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
