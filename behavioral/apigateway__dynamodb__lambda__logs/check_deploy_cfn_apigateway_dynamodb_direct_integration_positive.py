"""deploy-cfn-apigateway-dynamodb-direct-integration-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigateway-dynamodb-direct-integration-positive"
GROUP = "resource-binding"
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

  ApiGatewayRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: apigateway.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: ddb-put
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - dynamodb:PutItem
                Resource: !GetAtt DDBTable.Arn

  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub "${AWS::StackName}-api"

  ItemsResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: items

  ItemsMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref ItemsResource
      HttpMethod: POST
      AuthorizationType: NONE
      Integration:
        Type: AWS
        IntegrationHttpMethod: POST
        Credentials: !GetAtt ApiGatewayRole.Arn
        Uri: !Sub "arn:aws:apigateway:${AWS::Region}:dynamodb:action/PutItem"
        RequestTemplates:
          application/json: !Sub |
            {
              "TableName": "${DDBTable}",
              "Item": {
                "id": {"S": "$input.path('$.id')"},
                "value": {"S": "$input.path('$.value')"}
              }
            }
        IntegrationResponses:
          - StatusCode: '200'
            ResponseTemplates:
              application/json: '{"status": "written"}'
      MethodResponses:
        - StatusCode: '200'

  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: ItemsMethod
    Properties:
      RestApiId: !Ref RestApi

  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod

Outputs:
  ApiId:
    Value: !Ref RestApi
  TableName:
    Value: !Ref DDBTable
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed API Gateway AWS-service integration wired directly to DynamoDB PutItem
    (no Lambda) actually writes the item when called over HTTP, end-to-end."""
    result = _deploy_cfn(ctx, _TEMPLATE)
    api_url = f"{ctx.api_url(result['outputs']['ApiId'], 'prod')}/items"
    table_name = result["outputs"]["TableName"]

    item_id = ctx.unique_name("direct-item-")
    body = json.dumps({"id": item_id, "value": "hello-direct-integration"})

    status, response_body = _poll_until(
        lambda: _http_request("POST", api_url, body=body),
        lambda r: r[0] == 200,
        timeout_s=45.0,
        interval_s=3.0,
        description="direct-integration PutItem call succeeds",
    )
    assert status == 200, f"expected 200, got status={status} body={response_body}"
    assert json.loads(response_body)["status"] == "written"

    ddb = ctx.client("dynamodb")
    item = ddb.get_item(TableName=table_name, Key={"id": {"S": item_id}}).get("Item")
    assert item is not None, "PutItem via the direct API Gateway integration did not persist"
    assert item["value"]["S"] == "hello-direct-integration"


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
