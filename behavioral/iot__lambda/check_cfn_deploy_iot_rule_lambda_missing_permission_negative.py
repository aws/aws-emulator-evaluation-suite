"""cfn-deploy-iot-rule-lambda-missing-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-iot-rule-lambda-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]

# One stack, two identical rule->lambda wirings sharing an execution role: RuleA/FnA is missing
# its AWS::Lambda::Permission (the break under test); RuleB/FnB has one (in-file positive
# control), so a faithful emulator must tell the two apart.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  FunctionNameA:
    Type: String
  FunctionNameB:
    Type: String
  RoleName:
    Type: String
  RuleNameA:
    Type: String
  RuleNameB:
    Type: String
  TopicA:
    Type: String
  TopicB:
    Type: String
Resources:
  LambdaLogGroupA:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/${FunctionNameA}"
      RetentionInDays: 1
  LambdaLogGroupB:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/${FunctionNameB}"
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
                Resource:
                  - !GetAtt LambdaLogGroupA.Arn
                  - !GetAtt LambdaLogGroupB.Arn
  FunctionA:
    Type: AWS::Lambda::Function
    DependsOn: LambdaLogGroupA
    Properties:
      FunctionName: !Ref FunctionNameA
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
  FunctionB:
    Type: AWS::Lambda::Function
    DependsOn: LambdaLogGroupB
    Properties:
      FunctionName: !Ref FunctionNameB
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
  RuleA:
    Type: AWS::IoT::TopicRule
    Properties:
      RuleName: !Ref RuleNameA
      TopicRulePayload:
        Sql: !Sub "SELECT * FROM '${TopicA}'"
        AwsIotSqlVersion: "2016-03-23"
        RuleDisabled: false
        Actions:
          - Lambda:
              FunctionArn: !GetAtt FunctionA.Arn
  RuleB:
    Type: AWS::IoT::TopicRule
    Properties:
      RuleName: !Ref RuleNameB
      TopicRulePayload:
        Sql: !Sub "SELECT * FROM '${TopicB}'"
        AwsIotSqlVersion: "2016-03-23"
        RuleDisabled: false
        Actions:
          - Lambda:
              FunctionArn: !GetAtt FunctionB.Arn
  PermissionB:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref FunctionB
      Principal: iot.amazonaws.com
      SourceArn: !Sub "arn:aws:iot:${AWS::Region}:${AWS::AccountId}:rule/${RuleNameB}"
"""


# timing:real-time — metric: 60 s
@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Without an AWS::Lambda::Permission for the IoT rule action, publishing to the rule's topic never invokes
    the function and the rule action's Failure metric increases, while a permissioned sibling rule delivers."""
    function_a = _xname(ctx, "fn-a")
    function_b = _xname(ctx, "fn-b")
    role_name = _xname(ctx, "role")
    rule_a = _xname(ctx, "rule-a").replace("-", "_")
    rule_b = _xname(ctx, "rule-b").replace("-", "_")
    topic_a = _xname(ctx, "topic-a")
    topic_b = _xname(ctx, "topic-b")

    _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "FunctionNameA": function_a,
            "FunctionNameB": function_b,
            "RoleName": role_name,
            "RuleNameA": rule_a,
            "RuleNameB": rule_b,
            "TopicA": topic_a,
            "TopicB": topic_b,
        },
    )

    iot_data = ctx.client("iot-data")
    corr_a = ctx.unique_name("corr-a-")
    corr_b = ctx.unique_name("corr-b-")
    iot_data.publish(
        topic=topic_a, qos=0, payload=json.dumps({"correlation_id": corr_a}).encode("utf-8")
    )
    iot_data.publish(
        topic=topic_b, qos=0, payload=json.dumps({"correlation_id": corr_b}).encode("utf-8")
    )

    # Positive control: the correctly-permissioned rule/function still delivers.
    control_marker = _poll_for_log_marker(
        ctx, f"/aws/lambda/{function_b}", corr_b, timeout_s=90.0
    )
    assert control_marker is not None, "control rule (with permission) never invoked its lambda"

    # The broken rule's lambda must never have been invoked.
    broken_marker = _poll_for_log_marker(
        ctx, f"/aws/lambda/{function_a}", corr_a, timeout_s=20.0
    )
    assert broken_marker is None, (
        f"lambda without a resource policy grant was invoked anyway: {broken_marker!r}"
    )

    # The rule engine must record the invocation attempt as a failed action.
    failure_total = _wait_for_rule_action_metric(ctx, rule_a, "Failure", timeout_s=240.0)
    assert failure_total > 0, f"RuleAction Failure metric for {rule_a} never incremented"


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


def _wait_for_rule_action_metric(ctx, rule_name, metric_name, timeout_s=240.0, interval_s=15.0):
    """Poll CloudWatch for the AWS/IoT rule-action metric (Success|Failure) for rule_name.
    Discovers the exact ActionType dimension value via list_metrics instead of hardcoding it
    (the AWS docs don't enumerate the ActionType string used for the Lambda action)."""
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        metrics = cw.list_metrics(
            Namespace="AWS/IoT",
            MetricName=metric_name,
            Dimensions=[{"Name": "RuleName", "Value": rule_name}],
        )["Metrics"]
        if metrics:
            dims = metrics[0]["Dimensions"]
            now = time.time()
            stats = cw.get_metric_statistics(
                Namespace="AWS/IoT",
                MetricName=metric_name,
                Dimensions=dims,
                StartTime=now - 900,
                EndTime=now + 60,
                Period=60,
                Statistics=["Sum"],
            )["Datapoints"]
            total = sum(d["Sum"] for d in stats)
            if total > 0:
                return total
        time.sleep(interval_s)
    return 0.0


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
