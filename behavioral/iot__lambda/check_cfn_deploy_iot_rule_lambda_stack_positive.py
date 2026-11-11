"""cfn-deploy-iot-rule-lambda-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iot-rule-lambda-stack-positive"
GROUP = "deployment-order"
SERVICES = ["iot", "lambda"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  FunctionName:
    Type: String
  RoleName:
    Type: String
  RuleName:
    Type: String
  TopicName:
    Type: String
Resources:
  LambdaLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/${FunctionName}"
      RetentionInDays: 1
  LambdaExecRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: logs-write
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !GetAtt LambdaLogGroup.Arn
  LambdaFunction:
    Type: AWS::Lambda::Function
    DependsOn: LambdaLogGroup
    Properties:
      FunctionName: !Ref FunctionName
      Role: !GetAtt LambdaExecRole.Arn
      Handler: index.handler
      Runtime: python3.12
      Timeout: 15
      Code:
        ZipFile: |
          import json
          def handler(event, context):
              print("SIM2REAL_MARKER::" + json.dumps(event))
              return {"ok": True}
  IoTRule:
    Type: AWS::IoT::TopicRule
    Properties:
      RuleName: !Ref RuleName
      TopicRulePayload:
        Sql: !Sub "SELECT * FROM '${TopicName}'"
        AwsIotSqlVersion: "2016-03-23"
        RuleDisabled: false
        Actions:
          - Lambda:
              FunctionArn: !GetAtt LambdaFunction.Arn
  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref LambdaFunction
      Principal: iot.amazonaws.com
      SourceArn: !Sub "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:rule/${RuleName}"
Outputs:
  FunctionNameOut:
    Value: !Ref LambdaFunction
  LogGroupNameOut:
    Value: !Ref LambdaLogGroup
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack wiring AWS::IoT::TopicRule -> AWS::Lambda::Function via AWS::Lambda::Permission
    results in a live pipeline: publishing to the rule's topic actually invokes the function with
    the message payload, end to end (not just CREATE_COMPLETE)."""
    function_name = _xname(ctx, "fn")
    role_name = _xname(ctx, "role")
    rule_name = _xname(ctx, "rule").replace("-", "_")
    topic_name = _xname(ctx, "topic")

    _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "FunctionName": function_name,
            "RoleName": role_name,
            "RuleName": rule_name,
            "TopicName": topic_name,
        },
    )

    log_group_name = f"/aws/lambda/{function_name}"
    correlation_id = ctx.unique_name("corr-")

    iot_data = ctx.client("iot-data")
    iot_data.publish(
        topic=topic_name,
        qos=0,
        payload=json.dumps({"correlation_id": correlation_id, "temp": 42}).encode("utf-8"),
    )

    marker = _poll_for_log_marker(ctx, log_group_name, correlation_id, timeout_s=90.0)
    assert marker is not None, f"lambda was never invoked for correlation_id={correlation_id}"
    assert marker.startswith("SIM2REAL_MARKER::"), f"expected SIM2REAL_MARKER:: prefix, got {marker!r}"
    event = json.loads(marker[len("SIM2REAL_MARKER::") :])
    assert event["correlation_id"] == correlation_id, (
        f"expected correlation_id={correlation_id!r}, got {event.get('correlation_id')!r}"
    )
    assert event["temp"] == 42, f"expected temp=42, got {event.get('temp')!r}"


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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _poll_for_log_marker(ctx, log_group_name, needle, timeout_s=90.0, interval_s=5.0):
    """Poll a CloudWatch Logs log group for a log line containing `needle`; return the full
    line if found within timeout_s, else None (absence)."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            streams = logs.describe_log_streams(
                logGroupName=log_group_name, orderBy="LastEventTime", descending=True, limit=10
            )["logStreams"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            streams = []
        for stream in streams:
            events = logs.get_log_events(
                logGroupName=log_group_name,
                logStreamName=stream["logStreamName"],
                startFromHead=True,
            )["events"]
            for event in events:
                if needle in event["message"]:
                    return event["message"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
