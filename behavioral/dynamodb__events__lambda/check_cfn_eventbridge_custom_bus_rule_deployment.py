"""cfn-eventbridge-custom-bus-rule-deployment."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-eventbridge-custom-bus-rule-deployment"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed custom EventBridge bus + rule + Lambda target delivers an event published to
    that custom bus end to end (and is NOT reachable via the default bus)."""
    stack = _deploy_cfn(ctx, _TEMPLATE)
    bus_name = stack["outputs"]["BusName"]
    table_name = stack["outputs"]["TableName"]
    events = ctx.client("events")
    ddb = ctx.client("dynamodb")

    marker = ctx.unique_name("bus-marker-")

    def _get_item(mk: str, *, consistent: bool = False):
        try:
            return ddb.get_item(
                TableName=table_name, Key={"id": {"S": mk}}, ConsistentRead=consistent
            ).get("Item")
        except ClientError:
            return None

    def _scan_count(mk: str) -> int:
        resp = ddb.scan(
            TableName=table_name,
            FilterExpression="id = :id",
            ExpressionAttributeValues={":id": {"S": mk}},
            ConsistentRead=True,
            Select="COUNT",
        )
        return resp["Count"]

    t0 = time.monotonic()
    events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": "custom.sim2real.batch06.bus",
                "DetailType": "bus-event",
                "Detail": json.dumps({"test_marker": marker}),
            }
        ]
    )
    item = _poll_until(
        lambda: _get_item(marker),
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"item {marker} written via custom bus delivery",
    )
    positive_latency_s = time.monotonic() - t0
    assert item["source"]["S"] == "custom.sim2real.batch06.bus", (
        f"expected recorded source 'custom.sim2real.batch06.bus', got {item['source']!r}"
    )

    # Same event pattern published to the DEFAULT bus must NOT reach this rule (it's bound to
    # the custom bus only) — confirms bus scoping, not just pattern matching. Absence is bounded
    # by a calibrated window (>=3x the measured positive-control delivery latency) with repeated
    # independent reads, never a bare sleep-then-check — a shorter window would score a correct
    # but slower target as blocked, and a single eventually-consistent read could miss a real
    # cross-bus delivery.
    marker2 = ctx.unique_name("bus-marker-default-")
    events.put_events(
        Entries=[
            {
                "Source": "custom.sim2real.batch06.bus",
                "DetailType": "bus-event",
                "Detail": json.dumps({"test_marker": marker2}),
            }
        ]
    )
    window_s = max(3.0 * positive_latency_s, 20.0)
    poll_interval_s = max(1.0, min(2.0, window_s / 10.0))
    deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < deadline:
        item2 = _get_item(marker2, consistent=True)
        assert item2 is None, (
            f"event published to the default bus was delivered to the custom-bus-only rule "
            f"after {samples} sample(s): {item2!r}"
        )
        samples += 1
        time.sleep(poll_interval_s)
    assert samples >= 3, (
        f"only {samples} absence sample(s) taken over a {window_s:.1f}s window — too few to "
        f"bound absence"
    )

    scan_count = _scan_count(marker2)
    assert scan_count == 0, (
        f"independent Scan expected 0 items matching {marker2!r}, found {scan_count}"
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
Description: sim2real cfn-eventbridge-custom-bus-rule-deployment
Resources:
  CustomBus:
    Type: AWS::Events::EventBus
    Properties:
      Name: !Sub "sim2real-xsvc-bus-${AWS::StackName}"

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
      EventBusName: !Ref CustomBus
      EventPattern:
        source:
          - "custom.sim2real.batch06.bus"
        detail-type:
          - "bus-event"
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
  BusName:
    Value: !Ref CustomBus
  BusArn:
    Value: !GetAtt CustomBus.Arn
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
