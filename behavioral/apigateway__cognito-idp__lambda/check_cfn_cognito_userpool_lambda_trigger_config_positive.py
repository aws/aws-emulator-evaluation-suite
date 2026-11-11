"""cfn-cognito-userpool-lambda-trigger-config-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cognito-userpool-lambda-trigger-config-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN UserPool LambdaConfig.PreSignUp trigger wired to a specific function ARN is
    actually invoked by Cognito on SignUp, and its response mutation (auto-confirm) takes effect."""
    result = _deploy_cfn(ctx, _template())
    pool_id = result["outputs"]["UserPoolId"]
    client_id = result["outputs"]["ClientId"]

    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-trigger-user-")
    password = "Sim2Real!Passw0rd1"
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    signup = idp.sign_up(ClientId=client_id, Username=username, Password=password)
    assert signup["UserConfirmed"] is True, (
        "SignUp did not come back auto-confirmed -- the PreSignUp trigger did not run "
        f"(or was not the one configured on this pool): {signup}"
    )

    user = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "CONFIRMED", f"expected CONFIRMED after the trigger auto-confirmed, got {user['UserStatus']}"


def _template() -> str:
    code = (
        "def handler(event, context):\n"
        "    resp = event.get('response') or {}\n"
        "    resp['autoConfirmUser'] = True\n"
        "    resp['autoVerifyEmail'] = False\n"
        "    event['response'] = resp\n"
        "    return event\n"
    )
    template = {
        "Resources": {
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                },
            },
            "PreSignUpFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": code},
                },
            },
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "LambdaConfig": {"PreSignUp": {"Fn::GetAtt": ["PreSignUpFn", "Arn"]}},
                    "Policies": {
                        "PasswordPolicy": {
                            "MinimumLength": 8,
                            "RequireUppercase": True,
                            "RequireLowercase": True,
                            "RequireNumbers": True,
                            "RequireSymbols": True,
                        }
                    },
                },
            },
            "UserPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "UserPoolId": {"Ref": "UserPool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "Permission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "PreSignUpFn"},
                    "Principal": "cognito-idp.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["UserPool", "Arn"]},
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "ClientId": {"Value": {"Ref": "UserPoolClient"}},
            "FunctionName": {"Value": {"Ref": "PreSignUpFn"}},
        },
    }
    return json.dumps(template)


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
