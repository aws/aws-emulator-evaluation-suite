"""deploy-authorizer-cfn-enforces-identity-source."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-authorizer-cfn-enforces-identity-source"
GROUP = "server-side"
SERVICES = ["apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AuthorizerRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
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
      FunctionName: !Sub '${AWS::StackName}-authfn'
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt AuthorizerRole.Arn
      Timeout: 10
      Code:
        ZipFile: |
          def handler(event, context):
              token = event.get("authorizationToken")
              effect = "Allow" if token == "sim2real-secret-token" else "Deny"
              return {
                  "principalId": "sim2real-test-user",
                  "policyDocument": {
                      "Version": "2012-10-17",
                      "Statement": [
                          {
                              "Action": "execute-api:Invoke",
                              "Effect": effect,
                              "Resource": event["methodArn"],
                          }
                      ],
                  },
              }
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub '${AWS::StackName}-api'
  EchoResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref Api
      ParentId: !GetAtt Api.RootResourceId
      PathPart: echo
  Authorizer:
    Type: AWS::ApiGateway::Authorizer
    Properties:
      Name: !Sub '${AWS::StackName}-authorizer'
      RestApiId: !Ref Api
      Type: TOKEN
      IdentitySource: method.request.header.Authorization
      AuthorizerUri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${AuthorizerFunction.Arn}/invocations'
      AuthorizerResultTtlInSeconds: 0
  AuthorizerPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref AuthorizerFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/authorizers/${Authorizer}'
  # A placeholder, unauthenticated method on the root resource purely so the
  # Deployment below has at least one method to deploy; the actual method
  # under test is attached to EchoResource directly via PutMethod, after the
  # stack (and its CFN-created Authorizer) already exist.
  RootMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !GetAtt Api.RootResourceId
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: '200'
            ResponseTemplates:
              application/json: '{"message": "root"}'
      MethodResponses:
        - StatusCode: '200'
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn:
      - RootMethod
      - AuthorizerPermission
    Properties:
      RestApiId: !Ref Api
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref Api
      DeploymentId: !Ref ApiDeployment
      StageName: sim2real
Outputs:
  RestApiId:
    Value: !Ref Api
  ResourceId:
    Value: !Ref EchoResource
  AuthorizerId:
    Value: !Ref Authorizer
  StageName:
    Value: !Ref ApiStage
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PutMethod-added method on a CloudFormation-created TOKEN authorizer: TestInvokeMethod
    bypasses the authorizer, while the deployed stage returns 401 without the identitySource
    header, 403 on the authorizer's Deny and 200 on its Allow.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html"""
    _stack_name, outputs = _deploy_stack(ctx, _TEMPLATE)
    apigw = ctx.client("apigateway")
    rest_api_id = outputs["RestApiId"]
    resource_id = outputs["ResourceId"]
    authorizer_id = outputs["AuthorizerId"]
    stage_name = outputs["StageName"]

    apigw.put_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "authorized"}'},
    )
    apigw.create_deployment(restApiId=rest_api_id, stageName=stage_name)

    # TestInvokeMethod bypasses the custom authorizer on real AWS: it always
    # exercises the integration, with or without the identitySource header.
    resp_missing = apigw.test_invoke_method(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET")
    assert resp_missing["status"] == 200, (resp_missing["status"], resp_missing.get("body"))
    assert json.loads(resp_missing["body"]) == {"message": "authorized"}, resp_missing

    resp_present = apigw.test_invoke_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        headers={"Authorization": "sim2real-secret-token"},
    )
    assert resp_present["status"] == 200, resp_present
    assert json.loads(resp_present["body"]) == {"message": "authorized"}, resp_present

    # A REAL invocation through the deployed stage DOES enforce the
    # identitySource end to end via the authorizer function's own decision.
    url = f"{ctx.rest_api_url(rest_api_id, stage_name)}/echo"
    status_missing, body_missing = _poll_get(url, headers=None)
    assert status_missing == 401, (status_missing, body_missing)
    assert json.loads(body_missing) == {"message": "Unauthorized"}, f"unexpected 401 body {body_missing!r}"
    assert '"message": "authorized"' not in body_missing, body_missing

    status_wrong, body_wrong = _poll_get(url, headers={"Authorization": "not-the-right-token"})
    assert status_wrong == 403, (status_wrong, body_wrong)
    assert json.loads(body_wrong) == {
        "Message": "User is not authorized to access this resource with an explicit deny "
                   "in an identity-based policy"}, f"unexpected explicit-deny body {body_wrong!r}"
    assert '"message": "authorized"' not in body_wrong, body_wrong

    status_ok, body_ok = _poll_get(url, headers={"Authorization": "sim2real-secret-token"})
    assert status_ok == 200, (status_ok, body_ok)
    assert json.loads(body_ok) == {"message": "authorized"}, body_ok


def _invoke_get(url: str, headers: dict | None, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _poll_get(url: str, headers: dict | None, timeout_s: float = 60.0, interval_s: float = 3.0) -> tuple[int, str]:
    """Retry to ride out post-deploy propagation delay for a freshly created
    stage/method/authorizer wiring."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        status, body = _invoke_get(url, headers)
        last = (status, body)
        if status in (200, 401, 403):
            return status, body
        time.sleep(interval_s)
    return last


def _deploy_stack(ctx, template_body: str, parameters: dict | None = None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-agw-")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": ["CAPABILITY_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_stack(Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack(ctx, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack(ctx, stack_name, {"DELETE_COMPLETE"}, set(), missing_ok=True)


def _wait_for_stack(
    ctx,
    stack_name: str,
    ok_statuses: set,
    bad_statuses: set,
    missing_ok: bool = False,
    timeout_s: float = 420.0,
    interval_s: float = 6.0,
) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if missing_ok and "does not exist" in str(exc):
                return
            raise
        if not stacks:
            if missing_ok:
                return
            raise AssertionError(f"stack {stack_name} vanished unexpectedly")
        last_status = stacks[0]["StackStatus"]
        if last_status in ok_statuses:
            return
        if last_status in bad_statuses:
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
