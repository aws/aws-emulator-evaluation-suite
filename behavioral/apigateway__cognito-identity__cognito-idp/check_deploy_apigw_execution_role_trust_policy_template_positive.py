"""deploy-apigw-execution-role-trust-policy-template-positive."""
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

CHECK = "deploy-apigw-execution-role-trust-policy-template-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  AuthorizerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: {function_name}
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 10
      Code:
        ZipFile: |
          def handler(event, context):
              token = event.get('authorizationToken', '')
              effect = 'Allow' if token == 'allow-me' else 'Deny'
              return {{
                  'principalId': 'sim2real-user',
                  'policyDocument': {{
                      'Version': '2012-10-17',
                      'Statement': [{{
                          'Action': 'execute-api:Invoke',
                          'Effect': effect,
                          'Resource': event['methodArn']
                      }}]
                  }}
              }}
  ApiGatewayInvokeRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: {invoke_role_name}
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: apigateway.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: InvokeAuthorizerLambda
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: lambda:InvokeFunction
                Resource: !GetAtt AuthorizerFunction.Arn
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: {api_name}
  SecureResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: secure
  TokenAuthorizer:
    Type: AWS::ApiGateway::Authorizer
    Properties:
      Name: TokenAuthorizer
      RestApiId: !Ref RestApi
      Type: TOKEN
      AuthorizerUri: !Sub "arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}:lambda:path/2015-03-31/functions/${{AuthorizerFunction.Arn}}/invocations"
      AuthorizerCredentials: !GetAtt ApiGatewayInvokeRole.Arn
      IdentitySource: method.request.header.Authorization
      AuthorizerResultTtlInSeconds: 0
  SecureMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref SecureResource
      HttpMethod: GET
      AuthorizationType: CUSTOM
      AuthorizerId: !Ref TokenAuthorizer
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
      - SecureMethod
    Properties:
      RestApiId: !Ref RestApi
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: test
Outputs:
  ApiId:
    Value: !Ref RestApi
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An IAM role whose AssumeRolePolicyDocument trusts apigateway.amazonaws.com, wired as a
    TOKEN authorizer's AuthorizerCredentials, lets API Gateway invoke the authorizer Lambda
    directly (no Lambda resource policy) -- the role is usable without AccessDenied."""
    function_name = _xname(ctx, "authfn")
    invoke_role_name = _xname(ctx, "apigw-invoke-role")
    api_name = _xname(ctx, "api")
    template = _TEMPLATE.format(
        function_name=function_name, invoke_role_name=invoke_role_name, api_name=api_name
    )

    stack = _deploy_cfn(ctx, template)
    invoke_url = f"{ctx.rest_api_url(stack['outputs']['ApiId'], 'test')}/secure"

    # IAM role trust/propagation can lag a few seconds behind stack CREATE_COMPLETE; poll until
    # the authorizer stops 500-ing (which is what an untrusted/unusable AuthorizerCredentials
    # role produces) and settles on a definite Allow/Deny decision.
    status, body = _poll_until(
        lambda: _http_get(ctx, invoke_url, {"Authorization": "allow-me"}),
        lambda result: result[0] != 500,
        timeout_s=60.0,
        interval_s=3.0,
        description="authorizer-backed request to stop 500-ing (role trust becomes usable)",
    )
    assert status == 200, f"expected Allow decision to reach the integration, got {status}: {body!r}"
    parsed = json.loads(body)
    assert parsed["message"] == "ok", f"expected MOCK integration response {{'message': 'ok'}}, got {parsed!r}"

    status2, body2 = _http_get(ctx, invoke_url, {"Authorization": "deny-me"})
    assert status2 == 403, f"expected Deny decision to produce 403, got {status2}: {body2!r}"


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
