"""cfn-eventbridge-rule-lambda-target-deployment."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-eventbridge-rule-lambda-target-deployment"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed EventBridge Rule + Lambda Permission actually invokes the target on a
    matching event, and the invocation's payload flows through to a real side effect."""
    template = _TEMPLATE
    stack = _deploy_cfn(ctx, template)
    table_name = stack["outputs"]["TableName"]
    events = ctx.client("events")
    ddb = ctx.client("dynamodb")

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "Source": "custom.sim2real.batch06.rule1",
                "DetailType": "order-created",
                "Detail": json.dumps({"test_marker": marker, "amount": 42}),
            }
        ]
    )

    def _get_item():
        try:
            return ddb.get_item(TableName=table_name, Key={"id": {"S": marker}}).get("Item")
        except ClientError:
            return None

    item = _poll_until(
        _get_item,
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"item {marker} written by EventBridge-invoked Lambda",
    )
    assert item["source"]["S"] == "custom.sim2real.batch06.rule1", (
        f"expected recorded source 'custom.sim2real.batch06.rule1', got {item['source']['S']!r}"
    )
    assert item["detail_type"]["S"] == "order-created", (
        f"expected recorded detail-type 'order-created', got {item['detail_type']['S']!r}"
    )
    raw = json.loads(item["raw"]["S"])
    assert raw["detail"]["amount"] == 42, (
        f"expected event detail.amount 42, got {raw['detail'].get('amount')!r}"
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


_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real cfn-eventbridge-rule-lambda-target-deployment
Resources:
  RecorderTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH

  FunctionRole:
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
      Policies:
        - PolicyName: ddb-write
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: dynamodb:PutItem
                Resource: !GetAtt RecorderTable.Arn

  TargetFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt FunctionRole.Arn
      Timeout: 10
      Environment:
        Variables:
          TABLE_NAME: !Ref RecorderTable
      Code:
        ZipFile: |
          import boto3, json, os
          def handler(event, context):
              table = boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])
              detail = event.get('detail', {})
              marker = detail.get('test_marker', 'unknown')
              table.put_item(Item={
                  'id': marker,
                  'detail_type': event.get('detail-type', ''),
                  'source': event.get('source', ''),
                  'raw': json.dumps(event),
              })
              return {'ok': True}

  Rule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source:
          - "custom.sim2real.batch06.rule1"
        detail-type:
          - "order-created"
      Targets:
        - Id: target1
          Arn: !GetAtt TargetFunction.Arn

  InvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref TargetFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt Rule.Arn

Outputs:
  TableName:
    Value: !Ref RecorderTable
  FunctionName:
    Value: !Ref TargetFunction
  RuleName:
    Value: !Ref Rule
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
