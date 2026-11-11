"""cfn-deploy-eventbridge-lambda-target-missing-permission."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-lambda-target-missing-permission"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real eventbridge->lambda permission boundary check
Parameters:
  IncludePermission:
    Type: String
    AllowedValues: ["true", "false"]
    Default: "true"
Conditions:
  CreatePermission: !Equals [!Ref IncludePermission, "true"]
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
        detail-type: ["perm-test"]
      Targets:
        - Id: lambda-target
          Arn: !GetAtt LambdaFunction.Arn

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Condition: CreatePermission
    Properties:
      FunctionName: !Ref LambdaFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt EventRule.Arn

Outputs:
  QueueAUrl:
    Value: !Ref QueueA
  RuleName:
    Value: !Ref EventRule
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Omitting the AWS::Lambda::Permission for a rule's Lambda target means the function is
    never invoked; the same template WITH the permission (positive control) does invoke it."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    # --- broken: no AWS::Lambda::Permission ---
    broken = _deploy_cfn(ctx, _TEMPLATE, parameters={"IncludePermission": "false"})
    marker_broken = ctx.unique_name("marker-broken-")
    resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "perm-test",
                "Detail": json.dumps({"marker": marker_broken}),
            }
        ]
    )
    # put_events itself always succeeds; delivery is async
    assert resp["FailedEntryCount"] == 0, f"put_events on broken stack rejected an entry: {resp}"
    bodies = _collect_messages(sqs, broken["outputs"]["QueueAUrl"], timeout_s=40)
    assert not any(marker_broken in b for b in bodies), "lambda was invoked despite missing permission"

    # --- positive control: same template, permission included ---
    fixed = _deploy_cfn(ctx, _TEMPLATE, parameters={"IncludePermission": "true"})
    marker_fixed = ctx.unique_name("marker-fixed-")
    resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "perm-test",
                "Detail": json.dumps({"marker": marker_fixed}),
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"put_events on fixed stack rejected an entry: {resp}"
    bodies = _collect_messages(sqs, fixed["outputs"]["QueueAUrl"], timeout_s=90, marker=marker_fixed)
    assert any(marker_fixed in b for b in bodies), "positive control: lambda was never invoked"


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
