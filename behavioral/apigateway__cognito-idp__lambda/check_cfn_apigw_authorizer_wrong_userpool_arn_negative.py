"""cfn-apigw-authorizer-wrong-userpool-arn-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-apigw-authorizer-wrong-userpool-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN stack whose COGNITO_USER_POOLS authorizer ProviderARNs points at the wrong user pool
    rejects a perfectly valid token issued by the OTHER (real) pool, while a token from the pool
    the authorizer actually trusts is accepted on the same deployed API."""
    result = _deploy_cfn(ctx, _template())
    real_pool_id = result["outputs"]["RealPoolId"]
    real_client_id = result["outputs"]["RealClientId"]
    trusted_pool_id = result["outputs"]["TrustedPoolId"]
    trusted_client_id = result["outputs"]["TrustedClientId"]
    api_id = result["outputs"]["ApiId"]

    idp = ctx.client("cognito-idp")
    password = "Sim2Real!Passw0rd1"

    real_username = ctx.unique_name("sim2real-real-user-")
    idp.admin_create_user(UserPoolId=real_pool_id, Username=real_username, TemporaryPassword=password, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=real_pool_id, Username=real_username))
    idp.admin_set_user_password(UserPoolId=real_pool_id, Username=real_username, Password=password, Permanent=True)
    real_token = idp.admin_initiate_auth(
        UserPoolId=real_pool_id,
        ClientId=real_client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": real_username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]

    trusted_username = ctx.unique_name("sim2real-trusted-user-")
    idp.admin_create_user(
        UserPoolId=trusted_pool_id, Username=trusted_username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=trusted_pool_id, Username=trusted_username))
    idp.admin_set_user_password(UserPoolId=trusted_pool_id, Username=trusted_username, Password=password, Permanent=True)
    trusted_token = idp.admin_initiate_auth(
        UserPoolId=trusted_pool_id,
        ClientId=trusted_client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": trusted_username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]

    url = f"{ctx.rest_api_url(api_id, 'test')}/secure"

    # Positive control: the pool actually named in ProviderARNs is accepted.
    status, body = _poll_invoke_until(url, trusted_token, {200}, timeout_s=90, interval_s=3)
    assert status == 200, f"positive control failed: expected 200 for the trusted pool's token, got {status}: {body}"

    # Negative: the real pool's token is rejected because the authorizer names the OTHER pool.
    # One request: the positive control already showed the API is live, so a 200 here is a finding.
    status, body = _invoke(url, real_token)
    assert status == 401, f"expected 401 for a token from the mismatched pool, got {status}: {body}"
    payload = json.loads(body)
    assert payload == {"message": "Unauthorized"}, f"expected the gateway rejection body, got {payload}"


def _template() -> str:
    password_policy = {
        "MinimumLength": 8,
        "RequireUppercase": True,
        "RequireLowercase": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
    }
    template = {
        "Resources": {
            "RealPool": {"Type": "AWS::Cognito::UserPool", "Properties": {"Policies": {"PasswordPolicy": password_policy}}},
            "RealPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "UserPoolId": {"Ref": "RealPool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "TrustedPool": {"Type": "AWS::Cognito::UserPool", "Properties": {"Policies": {"PasswordPolicy": password_policy}}},
            "TrustedPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "UserPoolId": {"Ref": "TrustedPool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
            "Api": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Ref": "AWS::StackName"}, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
            },
            # ProviderARNs points ONLY at TrustedPool -- RealPool's tokens must be rejected.
            "Authorizer": {
                "Type": "AWS::ApiGateway::Authorizer",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "Name": "mismatched-authz",
                    "Type": "COGNITO_USER_POOLS",
                    "ProviderARNs": [{"Fn::GetAtt": ["TrustedPool", "Arn"]}],
                    "IdentitySource": "method.request.header.Authorization",
                },
            },
            "Res": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                    "PathPart": "secure",
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ResourceId": {"Ref": "Res"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "COGNITO_USER_POOLS",
                    "AuthorizerId": {"Ref": "Authorizer"},
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {"StatusCode": "200", "ResponseTemplates": {"application/json": '{"ok": true}'}}
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "Method",
                "Properties": {"RestApiId": {"Ref": "Api"}},
            },
            "Stage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {"RestApiId": {"Ref": "Api"}, "DeploymentId": {"Ref": "Deployment"}, "StageName": "test"},
            },
        },
        "Outputs": {
            "RealPoolId": {"Value": {"Ref": "RealPool"}},
            "RealClientId": {"Value": {"Ref": "RealPoolClient"}},
            "TrustedPoolId": {"Value": {"Ref": "TrustedPool"}},
            "TrustedClientId": {"Value": {"Ref": "TrustedPoolClient"}},
            "ApiId": {"Value": {"Ref": "Api"}},
        },
    }
    return json.dumps(template)


def _invoke(url: str, token: str | None = None, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    if token is not None:
        req.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_invoke_until(url: str, token: str | None, target_statuses: set[int], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status, body = _invoke(url, token)
        last = (status, body)
        if status in target_statuses:
            return status, body
        time.sleep(interval_s)
    raise AssertionError(f"never observed status in {target_statuses}; last={last}")


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
