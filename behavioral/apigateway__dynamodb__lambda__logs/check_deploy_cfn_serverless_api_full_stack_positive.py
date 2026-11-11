"""deploy-cfn-serverless-api-full-stack-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-serverless-api-full-stack-positive"
GROUP = "deployment-order"
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
          import json, os, time, boto3
          ddb = boto3.client('dynamodb')
          TABLE = os.environ['TABLE_NAME']
          def handler(event, context):
              item_id = context.aws_request_id
              ddb.put_item(TableName=TABLE, Item={'id': {'S': item_id}, 'ts': {'S': str(time.time())}})
              return {'statusCode': 200, 'headers': {'Content-Type': 'application/json'}, 'body': json.dumps({'id': item_id})}

  LambdaLogGroup:
    Type: AWS::Logs::LogGroup
    DependsOn: LambdaFunction
    Properties:
      LogGroupName: !Sub "/aws/lambda/${LambdaFunction}"
      RetentionInDays: 3

  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub "${AWS::StackName}-api"

  ApiResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: items

  ApiMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref ApiResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: AWS_PROXY
        IntegrationHttpMethod: POST
        Uri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaFunction.Arn}/invocations"

  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: ApiMethod
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
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/items"

Outputs:
  ApiId:
    Value: !Ref RestApi
  TableName:
    Value: !Ref DDBTable
  LogGroupName:
    Value: !Ref LambdaLogGroup
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A full CFN stack (DynamoDB + Lambda + API Gateway + Logs) is deployed and functions
    end-to-end: an HTTP call through the API invokes Lambda, which writes to DynamoDB and
    emits CloudWatch log entries."""
    result = _deploy_cfn(ctx, _TEMPLATE)
    api_url = f"{ctx.api_url(result['outputs']['ApiId'], 'prod')}/items"
    table_name = result["outputs"]["TableName"]
    log_group_name = result["outputs"]["LogGroupName"]

    # API Gateway stages can take a few seconds to become reachable after deploy.
    def _call_api():
        status, body = _http_request("GET", api_url)
        if status != 200:
            return None
        return json.loads(body)["id"]

    request_id = _poll_until(
        _call_api,
        lambda r: r is not None,
        timeout_s=45.0,
        interval_s=3.0,
        description="API endpoint returning 200",
    )

    ddb = ctx.client("dynamodb")
    item = _poll_until(
        lambda: ddb.get_item(TableName=table_name, Key={"id": {"S": request_id}}, ConsistentRead=True).get("Item"),
        lambda it: it is not None,
        timeout_s=20.0,
        interval_s=2.0,
        description="Lambda invocation writing the expected item to DynamoDB",
    )
    assert item["id"]["S"] == request_id, f"expected DynamoDB item id {request_id!r}, got {item['id']['S']!r}"

    logs = ctx.client("logs")
    current_id = {"value": request_id}

    def _find_log_event():
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name)
        except ClientError:
            return []
        events = resp.get("events", [])
        matches = [e for e in events if current_id["value"] in e["message"]]
        if matches:
            return matches
        # The first invocation's own log lines may not have landed yet (IAM log-write
        # permission propagation lag right after CREATE_COMPLETE) -- retrigger a fresh call
        # and track its request id so a later attempt can self-heal.
        new_id = _call_api()
        if new_id:
            current_id["value"] = new_id
        return []

    events = _poll_until(
        _find_log_event,
        lambda evts: len(evts) > 0,
        timeout_s=90.0,
        interval_s=6.0,
        description="CloudWatch log event referencing the request",
    )
    assert any(current_id["value"] in e["message"] for e in events), (
        f"no CloudWatch log event in {log_group_name!r} referenced request id {current_id['value']!r}: "
        f"{[e['message'] for e in events]!r}"
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
