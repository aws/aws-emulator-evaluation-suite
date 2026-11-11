"""deploy-cfn-missing-lambda-permission-for-apigateway-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-missing-lambda-permission-for-apigateway-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH

  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: inline-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - dynamodb:PutItem
                Resource: !GetAtt DDBTable.Arn
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 10
      Environment:
        Variables:
          TABLE_NAME: !Ref DDBTable
      Code:
        ZipFile: |
          import os, boto3
          ddb = boto3.client('dynamodb')
          TABLE = os.environ['TABLE_NAME']
          def handler(event, context):
              path = event.get('requestContext', {}).get('resourcePath', 'unknown')
              ddb.put_item(TableName=TABLE, Item={'id': {'S': path}})
              return {'statusCode': 200, 'body': 'ok:' + path}

  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub "${AWS::StackName}-api"

  NoPermResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: noperm

  NoPermMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref NoPermResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: AWS_PROXY
        IntegrationHttpMethod: POST
        Uri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations"

  WithPermResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: withperm

  WithPermMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref WithPermResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: AWS_PROXY
        IntegrationHttpMethod: POST
        Uri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations"

  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn:
      - NoPermMethod
      - WithPermMethod
    Properties:
      RestApiId: !Ref RestApi

  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref LambdaFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/GET/withperm"

Outputs:
  ApiId:
    Value: !Ref RestApi
  TableName:
    Value: !Ref DDBTable
"""


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A method whose Lambda::Permission SourceArn does not cover it fails to invoke Lambda
    (no downstream effect), while a sibling method on the same function scoped correctly by
    the permission succeeds — proving the block is the missing permission, not a broken stack."""
    result = _deploy_cfn(ctx, _TEMPLATE)
    stage_url = ctx.api_url(result["outputs"]["ApiId"], "prod")
    no_perm_url = f"{stage_url}/noperm"
    with_perm_url = f"{stage_url}/withperm"
    table_name = result["outputs"]["TableName"]
    ddb = ctx.client("dynamodb")

    # Positive control first: the correctly-scoped path must actually work.
    status, body = _poll_until(
        lambda: _http_request("GET", with_perm_url),
        lambda r: r[0] in (200, 500),
        timeout_s=45.0,
        interval_s=3.0,
        description="withperm endpoint reachable",
    )
    assert status == 200, f"positive control failed: status={status} body={body}"
    # The Lambda writes the item keyed by requestContext.resourcePath, which API Gateway
    # renders WITH a leading slash (e.g. "/withperm"), not the bare path part.
    with_perm_item = ddb.get_item(TableName=table_name, Key={"id": {"S": "/withperm"}}, ConsistentRead=True).get("Item")
    assert with_perm_item is not None, f"expected Lambda to have written /withperm to {table_name}, found no item"


    # Negative: the unscoped path must be denied at the API Gateway -> Lambda boundary.
    status, body = _http_request("GET", no_perm_url)
    assert status == 500, f"expected 500 Internal server error, got status={status} body={body}"
    parsed = json.loads(body)
    assert parsed.get("message") == "Internal server error", f"expected message 'Internal server error', got {parsed!r}"
    assert ddb.get_item(TableName=table_name, Key={"id": {"S": "/noperm"}}).get("Item") is None, (
        "Lambda was invoked despite the missing resource-based permission"
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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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


def _http_request(method, url, body=None, timeout=15):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
