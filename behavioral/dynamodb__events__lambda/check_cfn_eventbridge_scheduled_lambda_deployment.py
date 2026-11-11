"""cfn-eventbridge-scheduled-lambda-deployment."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-eventbridge-scheduled-lambda-deployment"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "events", "lambda"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A deployed EventBridge scheduled rule (rate(1 minute)) actually invokes the associated
    Lambda on its own, without any external trigger, and the invocation has an observable
    side effect."""
    stack = _deploy_cfn(ctx, _TEMPLATE)
    table_name = stack["outputs"]["TableName"]
    ddb = ctx.client("dynamodb")

    def _first_tick():
        items = ddb.scan(TableName=table_name, Limit=1)["Items"]
        return items[0] if items else None

    # EventBridge schedule granularity is 1 minute (rate(1 minute)); give it up to ~2.5
    # scheduling windows to fire at least once before failing.
    before = time.time()
    item = _poll_until(
        _first_tick,
        lambda i: i is not None,
        timeout_s=150.0,
        interval_s=10.0,
        description="at least one scheduled tick recorded",
    )
    # The predicate above only proves "a row exists" — that a target could satisfy by seeding
    # the table itself. Pin the row to the live invocation: `id` must be the Lambda request id
    # the handler was actually given, and `ts` must be a clock reading taken during our own
    # poll window, not a value a stub could have precomputed.
    request_id = item["id"]["S"]
    assert re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", request_id), (
        f"expected the recorded id to be a Lambda request id (UUID), got {request_id!r}"
    )
    ts = float(item["ts"]["S"])
    age_s = time.time() - ts
    assert -5.0 <= age_s <= 200.0, (
        f"expected the tick's recorded timestamp to fall within our own poll window "
        f"(started {time.time() - before:.1f}s ago), got age={age_s:.1f}s (ts={ts})"
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
Description: sim2real cfn-eventbridge-scheduled-lambda-deployment
Resources:
  TicksTable:
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
                Resource: !GetAtt TicksTable.Arn

  TickFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt FunctionRole.Arn
      Timeout: 10
      Environment:
        Variables:
          TABLE_NAME: !Ref TicksTable
      Code:
        ZipFile: |
          import boto3, os, time
          def handler(event, context):
              table = boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])
              table.put_item(Item={'id': context.aws_request_id, 'ts': str(time.time())})
              return {'ok': True}

  ScheduleRule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: rate(1 minute)
      State: ENABLED
      Targets:
        - Id: tick
          Arn: !GetAtt TickFunction.Arn

  InvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref TickFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt ScheduleRule.Arn

Outputs:
  TableName:
    Value: !Ref TicksTable
  RuleName:
    Value: !Ref ScheduleRule
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
