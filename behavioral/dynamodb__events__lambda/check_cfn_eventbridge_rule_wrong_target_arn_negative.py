"""cfn-eventbridge-rule-wrong-target-arn-negative."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-eventbridge-rule-wrong-target-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stack rule whose target ARN names a function that does not exist (GetFunction: ResourceNotFoundException
    "Function not found: <arn>") reports FailedInvocations >= 1 for a matching event, while the sibling rule
    with a real target delivers end to end.
    """
    bad_function_name = ctx.unique_name("sim2real-xsvc-nonexistent-")[:64]
    stack = _deploy_cfn(ctx, _TEMPLATE, parameters={"BadFunctionName": bad_function_name})
    good_table = stack["outputs"]["GoodTableName"]
    bad_rule_name = stack["outputs"]["BadRuleName"]
    events = ctx.client("events")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    # The fabricated target was never created — confirm it genuinely does not exist.
    code, message = _error(lambda: lam.get_function(FunctionName=bad_function_name))
    assert code == "ResourceNotFoundException", (
        f"expected GetFunction({bad_function_name}) to report ResourceNotFoundException "
        f"(the bad rule's target must genuinely not exist); got {code!r}: {message!r}"
    )
    assert message == f"Function not found: {stack['outputs']['BadTargetArn']}", message

    # Positive control: the sibling rule with a real target delivers.
    good_marker = ctx.unique_name("good-marker-")
    events.put_events(
        Entries=[
            {
                "Source": "custom.sim2real.batch06.good",
                "DetailType": "ok",
                "Detail": json.dumps({"test_marker": good_marker}),
            }
        ]
    )

    def _get_good():
        try:
            return ddb.get_item(TableName=good_table, Key={"id": {"S": good_marker}}).get("Item")
        except ClientError:
            return None

    _poll_until(
        _get_good,
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"good item {good_marker} delivered via correctly-wired rule",
    )

    # Break exactly one thing (the bad rule's target ARN points nowhere): publish a matching
    # event and confirm EventBridge itself reports the delivery as failed.
    events.put_events(
        Entries=[
            {
                "Source": "custom.sim2real.batch06.bad",
                "DetailType": "bad",
                "Detail": json.dumps({"note": "should never be delivered anywhere"}),
            }
        ]
    )

    def _failed_invocations_sum() -> float:
        now = datetime.now(timezone.utc)
        resp = cw.get_metric_statistics(
            Namespace="AWS/Events",
            MetricName="FailedInvocations",
            Dimensions=[{"Name": "RuleName", "Value": bad_rule_name}],
            StartTime=now - timedelta(minutes=20),
            EndTime=now + timedelta(minutes=1),
            Period=60,
            Statistics=["Sum"],
        )
        return sum(dp["Sum"] for dp in resp.get("Datapoints", []))

    # CloudWatch metric ingestion for EventBridge is not instantaneous; poll generously rather
    # than asserting immediately (see "Detecting event delivery failures" in the EventBridge
    # user guide).
    total = _poll_until(
        _failed_invocations_sum,
        lambda s: s >= 1,
        timeout_s=400.0,
        interval_s=20.0,
        description=f"FailedInvocations>=1 for rule {bad_rule_name}",
    )
    assert total >= 1, (
        f"expected FailedInvocations>=1 for rule {bad_rule_name} after publishing a matching "
        f"event to a rule whose target ARN points at a function that never existed; got {total}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error(fn):
    """Return (Error.Code, Error.Message) of the refusal fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


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
Description: sim2real cfn-eventbridge-rule-wrong-target-arn-negative
Parameters:
  BadFunctionName:
    Type: String

Resources:
  GoodTable:
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
                Resource: !GetAtt GoodTable.Arn

  GoodFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt FunctionRole.Arn
      Timeout: 10
      Environment:
        Variables:
          TABLE_NAME: !Ref GoodTable
      Code:
        ZipFile: |
          import boto3, json, os
          def handler(event, context):
              table = boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])
              detail = event.get('detail', {})
              marker = detail.get('test_marker', 'unknown')
              table.put_item(Item={'id': marker, 'raw': json.dumps(event)})
              return {'ok': True}

  GoodRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source:
          - "custom.sim2real.batch06.good"
        detail-type:
          - "ok"
      Targets:
        - Id: target1
          Arn: !GetAtt GoodFunction.Arn

  GoodInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref GoodFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt GoodRule.Arn

  BadRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source:
          - "custom.sim2real.batch06.bad"
        detail-type:
          - "bad"
      Targets:
        - Id: badtarget
          Arn: !Sub "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:${BadFunctionName}"

Outputs:
  GoodTableName:
    Value: !Ref GoodTable
  BadRuleName:
    Value: !Ref BadRule
  BadTargetArn:
    Value: !Sub "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:${BadFunctionName}"
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
