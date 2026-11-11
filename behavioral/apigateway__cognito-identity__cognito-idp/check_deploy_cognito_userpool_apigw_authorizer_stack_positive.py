"""deploy-cognito-userpool-apigw-authorizer-stack-positive."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-userpool-apigw-authorizer-stack-positive"
GROUP = "deploy-behavior"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

_TEST_PASSWORD = "Sim2Real!Test123"

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  UserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: {pool_name}
  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties:
      UserPoolId: !Ref UserPool
      ClientName: {client_name}
      GenerateSecret: false
      ExplicitAuthFlows:
        - ALLOW_ADMIN_USER_PASSWORD_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: {api_name}
  HelloResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: hello
  CognitoAuthorizer:
    Type: AWS::ApiGateway::Authorizer
    Properties:
      Name: CognitoAuthorizer
      RestApiId: !Ref RestApi
      Type: COGNITO_USER_POOLS
      IdentitySource: method.request.header.Authorization
      ProviderARNs:
        - !GetAtt UserPool.Arn
  HelloMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref HelloResource
      HttpMethod: GET
      AuthorizationType: COGNITO_USER_POOLS
      AuthorizerId: !Ref CognitoAuthorizer
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{{"statusCode": 200}}'
        IntegrationResponses:
          - StatusCode: "200"
            ResponseTemplates:
              application/json: '{{"message":"ok"}}'
      MethodResponses:
        - StatusCode: "200"
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn:
      - HelloMethod
    Properties:
      RestApiId: !Ref RestApi
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: test
Outputs:
  UserPoolId:
    Value: !Ref UserPool
  UserPoolClientId:
    Value: !Ref UserPoolClient
  ApiId:
    Value: !Ref RestApi
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN stack deploying a User Pool + REST API with a COGNITO_USER_POOLS authorizer
    lets a valid pool ID token through and rejects requests carrying no token at all."""
    pool_name = _xname(ctx, "pool")
    client_name = _xname(ctx, "client")
    api_name = _xname(ctx, "api")
    template = _TEMPLATE.format(pool_name=pool_name, client_name=client_name, api_name=api_name)

    stack = _deploy_cfn(ctx, template)
    user_pool_id = stack["outputs"]["UserPoolId"]
    client_id = stack["outputs"]["UserPoolClientId"]
    invoke_url = f"{ctx.rest_api_url(stack['outputs']['ApiId'], 'test')}/hello"

    id_token = _create_user_and_get_id_token(ctx, user_pool_id, client_id)

    # API Gateway deployments/authorizer wiring can take a few seconds to become fully live.
    status, body = _poll_until(
        lambda: _http_get(ctx, invoke_url, {"Authorization": id_token}),
        lambda result: result[0] == 200,
        timeout_s=60.0,
        interval_s=3.0,
        description="authenticated request to reach 200",
    )
    assert status == 200, f"expected 200 for a valid Cognito ID token, got {status}: {body!r}"
    msg = json.loads(body)["message"]
    assert msg == "ok", f"expected the MOCK integration body to reach the caller, got message={msg!r}"

    # No Authorization header at all -> the authorizer rejects the call outright.
    status2, body2 = _http_get(ctx, invoke_url, {})
    assert status2 == 401, f"expected 401 with no Authorization header, got {status2}: {body2!r}"
    msg2 = json.loads(body2)["message"]
    assert msg2 == "Unauthorized", f"expected the default gateway 'Unauthorized' response, got message={msg2!r}"


_XSVC_PREFIX = "sim2real-xsvc-"


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
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
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


def _create_user_and_get_id_token(ctx, user_pool_id: str, client_id: str) -> str:
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-xsvc-user-")
    idp.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        TemporaryPassword=_TEST_PASSWORD,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=_TEST_PASSWORD, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _TEST_PASSWORD},
    )
    return auth["AuthenticationResult"]["IdToken"]


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_get(ctx, url: str, headers: dict[str, str]):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_context(ctx)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
