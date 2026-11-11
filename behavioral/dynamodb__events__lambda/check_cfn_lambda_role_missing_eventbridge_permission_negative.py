"""cfn-lambda-role-missing-eventbridge-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-role-missing-eventbridge-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role omits events:PutEvents fails to deliver events to
    EventBridge (AccessDeniedException, no downstream delivery) — while a caller that DOES
    have permission to publish the exact same event still gets it delivered end to end."""
    stack = _deploy_cfn(ctx, _TEMPLATE)
    table_name = stack["outputs"]["TableName"]
    caller_function = stack["outputs"]["CallerFunctionName"]
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    events = ctx.client("events")

    # Break exactly one thing: invoke the Lambda whose role has NO events:PutEvents policy.
    denied_marker = ctx.unique_name("denied-")
    resp = lam.invoke(
        FunctionName=caller_function,
        Payload=json.dumps(
            {
                "source": "custom.sim2real.batch06.neg1",
                "detail_type": "relay",
                "detail": {"test_marker": denied_marker},
            }
        ).encode(),
    )
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"unexpected lambda runtime error: {body}"
    assert body.get("error_code") == "AccessDeniedException", (
        f"expected AccessDeniedException from the permission-less caller, got: {body}"
    )

    # (b) the effect is ABSENT: no relay ever reaches the recorder table for the denied marker.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        found = ddb.get_item(TableName=table_name, Key={"id": {"S": denied_marker}}).get("Item")
        assert found is None, f"denied event was delivered anyway: {found}"
        time.sleep(3)

    # (c) positive control in the SAME file: a caller WITH permission (the test's own creds)
    # publishing the identical event through the identical rule/target IS delivered.
    control_marker = ctx.unique_name("control-")
    events.put_events(
        Entries=[
            {
                "Source": "custom.sim2real.batch06.neg1",
                "DetailType": "relay",
                "Detail": json.dumps({"test_marker": control_marker}),
            }
        ]
    )

    def _get_control():
        try:
            return ddb.get_item(TableName=table_name, Key={"id": {"S": control_marker}}).get("Item")
        except ClientError:
            return None

    item = _poll_until(
        _get_control,
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"control item {control_marker} delivered via the same rule/target",
    )
    assert item["source"]["S"] == "custom.sim2real.batch06.neg1", (
        f"control item {control_marker} has unexpected source: {item['source']}"
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
Description: sim2real cfn-lambda-role-missing-eventbridge-permission-negative
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

  RelayRole:
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

  RelayFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt RelayRole.Arn
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
                  'source': event.get('source', ''),
                  'raw': json.dumps(event),
              })
              return {'ok': True}

  Rule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source:
          - "custom.sim2real.batch06.neg1"
        detail-type:
          - "relay"
      Targets:
        - Id: target1
          Arn: !GetAtt RelayFunction.Arn

  InvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref RelayFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt Rule.Arn

  CallerRole:
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
      # Deliberately NO events:PutEvents permission anywhere on this role.

  CallerFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt CallerRole.Arn
      Timeout: 10
      Code:
        ZipFile: |
          import boto3, json
          from botocore.exceptions import ClientError
          def handler(event, context):
              client = boto3.client('events')
              try:
                  client.put_events(Entries=[{
                      'Source': event['source'],
                      'DetailType': event['detail_type'],
                      'Detail': json.dumps(event['detail']),
                  }])
                  return {'sent': True}
              except ClientError as e:
                  return {'error_code': e.response['Error']['Code']}

Outputs:
  TableName:
    Value: !Ref RecorderTable
  CallerFunctionName:
    Value: !Ref CallerFunction
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
