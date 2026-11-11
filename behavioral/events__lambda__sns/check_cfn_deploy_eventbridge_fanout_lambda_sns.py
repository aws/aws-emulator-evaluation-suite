"""cfn-deploy-eventbridge-fanout-lambda-sns."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-fanout-lambda-sns"
GROUP = "deployment-order"
SERVICES = ["events", "lambda", "sns"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real fanout check - one rule, two targets (lambda + sns)
Resources:
  QueueA:
    Type: AWS::SQS::Queue

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Service: lambda.amazonaws.com }
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: SendToQueueA
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !GetAtt QueueA.Arn

  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaRole.Arn
      Timeout: 15
      Environment:
        Variables:
          QUEUE_URL: !Ref QueueA
      Code:
        ZipFile: |
          import boto3, json, os
          sqs = boto3.client('sqs')
          def handler(event, context):
              sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))
              return {'ok': True}

  EventRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: ["sim2real.test"]
        detail-type: ["fanout-test"]
      Targets:
        - Id: lambda-target
          Arn: !GetAtt LambdaFunction.Arn
        - Id: sns-target
          Arn: !Ref SnsTopic

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref LambdaFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt EventRule.Arn

  SnsTopic:
    Type: AWS::SNS::Topic

  SnsTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SnsTopic]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal: { Service: events.amazonaws.com }
            Action: sns:Publish
            Resource: !Ref SnsTopic
            Condition:
              ArnEquals:
                aws:SourceArn: !GetAtt EventRule.Arn

  QueueB:
    Type: AWS::SQS::Queue

  QueueBPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref QueueB]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: AllowSnsSend
            Effect: Allow
            Principal: { Service: sns.amazonaws.com }
            Action: sqs:SendMessage
            Resource: !GetAtt QueueB.Arn
            Condition:
              ArnEquals:
                aws:SourceArn: !Ref SnsTopic

  Subscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref SnsTopic
      Protocol: sqs
      Endpoint: !GetAtt QueueB.Arn

Outputs:
  QueueAUrl:
    Value: !Ref QueueA
  QueueBUrl:
    Value: !Ref QueueB
  TopicArn:
    Value: !Ref SnsTopic
  FunctionName:
    Value: !Ref LambdaFunction
  RuleName:
    Value: !Ref EventRule
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule with a Lambda target and an SNS target both receive a matching event."""
    stack = _deploy_cfn(ctx, _TEMPLATE)
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    marker = ctx.unique_name("marker-")
    resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "fanout-test",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, (
        f"expected 0 failed entries, got {resp['FailedEntryCount']}: {resp.get('Entries')}"
    )

    lambda_bodies = _collect_messages(
        sqs, stack["outputs"]["QueueAUrl"], timeout_s=90, marker=marker
    )
    assert any(marker in b for b in lambda_bodies), "lambda target was never invoked"
    lambda_event = json.loads(next(b for b in lambda_bodies if marker in b))
    assert lambda_event["detail"]["marker"] == marker, (
        f"expected detail.marker {marker!r}, got {lambda_event['detail'].get('marker')!r}"
    )
    assert lambda_event["source"] == "sim2real.test", (
        f"expected source 'sim2real.test', got {lambda_event['source']!r}"
    )

    sns_bodies = _collect_messages(
        sqs, stack["outputs"]["QueueBUrl"], timeout_s=90, marker=marker
    )
    assert any(marker in b for b in sns_bodies), "sns target was never published to"
    envelope = json.loads(next(b for b in sns_bodies if marker in b))
    assert envelope["Type"] == "Notification", (
        f"expected SNS envelope Type 'Notification', got {envelope['Type']!r}"
    )
    assert envelope["TopicArn"] == stack["outputs"]["TopicArn"], (
        f"expected TopicArn {stack['outputs']['TopicArn']!r}, got {envelope['TopicArn']!r}"
    )
    assert marker in envelope["Message"], (
        f"expected marker {marker!r} in SNS Message, got {envelope['Message']!r}"
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


def _collect_messages(sqs, queue_url, *, timeout_s, marker=None):
    """Long-poll a queue up to timeout_s, returning bodies collected (deleting them as read)."""
    deadline = time.monotonic() + timeout_s
    found: list[str] = []
    while time.monotonic() < deadline:
        remaining = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for msg in resp.get("Messages", []):
            found.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if marker and any(marker in b for b in found):
            return found
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
