"""deploy-cfn-lambda-log-group-retention-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-log-group-retention-positive"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_RETENTION_DAYS = 3

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
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
        - PolicyName: inline-logs
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 10
      Code:
        ZipFile: |
          def handler(event, context):
              print("retention-check-marker")
              return {"ok": True}

  ExplicitLogGroup:
    Type: AWS::Logs::LogGroup
    DependsOn: LambdaFunction
    Properties:
      LogGroupName: !Sub "/aws/lambda/${LambdaFunction}"
      RetentionInDays: %d

Outputs:
  FunctionName:
    Value: !Ref LambdaFunction
  LogGroupName:
    Value: !Ref ExplicitLogGroup
""" % _RETENTION_DAYS


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-declared explicit LogGroup RetentionInDays for a Lambda function's log group is
    reflected by describe_log_groups, and the log group actually receives the function's
    log output post-deploy."""
    result = _deploy_cfn(ctx, _TEMPLATE)
    function_name = result["outputs"]["FunctionName"]
    log_group_name = result["outputs"]["LogGroupName"]

    logs = ctx.client("logs")
    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    matching = [g for g in groups if g["logGroupName"] == log_group_name]
    assert len(matching) == 1, f"expected exactly one log group named {log_group_name}"
    assert matching[0]["retentionInDays"] == _RETENTION_DAYS, (
        f"expected retentionInDays={_RETENTION_DAYS}, got {matching[0]['retentionInDays']}"
    )

    lambda_client = ctx.client("lambda")
    lambda_client.invoke(FunctionName=function_name, InvocationType="RequestResponse")

    def _find_marker():
        # Re-invoke on each poll: the execution role's logs permissions may not have
        # propagated yet for the very first invoke right after stack CREATE_COMPLETE, so a
        # single invocation can silently fail to deliver its log lines. Retriggering lets a
        # later attempt succeed once IAM has propagated.
        try:
            lambda_client.invoke(FunctionName=function_name, InvocationType="RequestResponse")
        except ClientError:
            pass
        try:
            # filter_log_events' unstructured-log filter pattern syntax requires terms
            # containing non-alphanumeric characters (our marker has hyphens) to be quoted,
            # or matching silently misbehaves -- fetch unfiltered and match the substring
            # locally instead.
            resp = logs.filter_log_events(logGroupName=log_group_name)
        except ClientError:
            return []
        return [e for e in resp.get("events", []) if "retention-check-marker" in e["message"]]


    events = _poll_until(
        _find_marker,
        lambda evts: len(evts) > 0,
        timeout_s=90.0,
        interval_s=8.0,
        description="Lambda log marker delivered to the retention-configured log group",
    )
    assert len(events) > 0, f"expected at least one delivered marker event, got {events!r}"


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
