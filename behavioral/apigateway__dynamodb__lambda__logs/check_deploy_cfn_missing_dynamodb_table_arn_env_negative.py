"""deploy-cfn-missing-dynamodb-table-arn-env-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-missing-dynamodb-table-arn-env-negative"
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
                  - dynamodb:GetItem
                Resource: '*'
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  LambdaCode:
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
          from botocore.exceptions import ClientError
          ddb = boto3.client('dynamodb')
          TABLE = os.environ['TABLE_NAME']
          def handler(event, context):
              item_id = event['id']
              try:
                  ddb.put_item(TableName=TABLE, Item={'id': {'S': item_id}})
                  return {'ok': True, 'id': item_id}
              except ClientError as e:
                  return {'ok': False, 'error': e.response['Error']['Code'], 'id': item_id}

  LambdaWrongTable:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 10
      Environment:
        Variables:
          TABLE_NAME: !Sub "${DDBTable}-typo-nonexistent"
      Code:
        ZipFile: |
          import os, boto3
          from botocore.exceptions import ClientError
          ddb = boto3.client('dynamodb')
          TABLE = os.environ['TABLE_NAME']
          def handler(event, context):
              item_id = event['id']
              try:
                  ddb.put_item(TableName=TABLE, Item={'id': {'S': item_id}})
                  return {'ok': True, 'id': item_id}
              except ClientError as e:
                  return {'ok': False, 'error': e.response['Error']['Code'], 'id': item_id}

Outputs:
  TableName:
    Value: !Ref DDBTable
  CorrectFunctionName:
    Value: !Ref LambdaCode
  WrongFunctionName:
    Value: !Ref LambdaWrongTable
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose DynamoDB table-name environment variable points at a
    non-existent table fails every PutItem with ResourceNotFoundException and writes nothing,
    while an identical function pointed at the real table (the positive control) succeeds."""
    result = _deploy_cfn(ctx, _TEMPLATE)
    table_name = result["outputs"]["TableName"]
    correct_fn = result["outputs"]["CorrectFunctionName"]
    wrong_fn = result["outputs"]["WrongFunctionName"]
    lambda_client = ctx.client("lambda")
    ddb = ctx.client("dynamodb")

    good_id = ctx.unique_name("good-")
    resp = lambda_client.invoke(
        FunctionName=correct_fn, InvocationType="RequestResponse", Payload=json.dumps({"id": good_id}).encode()
    )
    payload = json.loads(resp["Payload"].read())
    assert payload["ok"] is True, f"positive control failed: {payload}"
    assert ddb.get_item(TableName=table_name, Key={"id": {"S": good_id}}).get("Item") is not None, (
        f"positive control item {good_id!r} not found in {table_name!r} after successful put_item"
    )

    bad_id = ctx.unique_name("bad-")
    resp = lambda_client.invoke(
        FunctionName=wrong_fn, InvocationType="RequestResponse", Payload=json.dumps({"id": bad_id}).encode()
    )
    payload = json.loads(resp["Payload"].read())
    assert payload["ok"] is False, f"expected the mistargeted put_item to fail, got: {payload}"
    assert payload["error"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the nonexistent table, got: {payload['error']!r}"
    )
    assert ddb.get_item(TableName=table_name, Key={"id": {"S": bad_id}}).get("Item") is None, (
        "item leaked into the real table despite targeting a non-existent table name"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
