"""cfn-ddb-stream-esm-lambda-deployment."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ddb-stream-esm-lambda-deployment"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed DynamoDB table StreamSpecification + Lambda EventSourceMapping actually
    triggers the function on table writes, and the function's own DynamoDB write lands."""
    stack = _deploy_cfn(ctx, _TEMPLATE)
    source_table = stack["outputs"]["SourceTableName"]
    sink_table = stack["outputs"]["SinkTableName"]
    esm_id = stack["outputs"]["EsmId"]
    lam = ctx.client("lambda")
    ddb = ctx.client("dynamodb")

    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_id)["State"],
        lambda s: s == "Enabled",
        timeout_s=120.0,
        interval_s=5.0,
        description=f"event source mapping {esm_id} Enabled",
    )

    # Even once the mapping reports Enabled, the poller needs a bit of warm-up time to
    # establish its shard iterator (and any IAM propagation for the stream-read permissions
    # to take effect) before it will actually pick up new records. If the poller's first few
    # reads hit AccessDenied while the managed-policy attachment is still propagating, Lambda's
    # ESM backs off for a while before retrying. Rather than a fixed sleep, that warm-up is
    # absorbed by the retry window below: the deadline is generous enough to cover it, and the
    # loop returns as soon as the sink write actually lands.
    pk = None
    last_item = None
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline and last_item is None:
        if pk is None:
            pk = ctx.unique_name("stream-pk-")
            ddb.put_item(TableName=source_table, Item={"pk": {"S": pk}, "payload": {"S": "hello"}})
        try:
            last_item = ddb.get_item(TableName=sink_table, Key={"id": {"S": pk}}).get("Item")
        except ClientError:
            last_item = None
        if last_item is None:
            time.sleep(5.0)

    if last_item is None:
        debug = _recent_lambda_logs(ctx, stack["outputs"].get("FunctionName", ""))
        try:
            mapping = lam.get_event_source_mapping(UUID=esm_id)
            esm_debug = (
                f"State={mapping.get('State')} StateTransitionReason={mapping.get('StateTransitionReason')} "
                f"LastProcessingResult={mapping.get('LastProcessingResult')}"
            )
        except ClientError as e:
            esm_debug = f"<esm describe failed: {e}>"
        raise AssertionError(
            f"sink item {pk} written by stream-triggered Lambda not observed within the wait window. "
            f"esm: {esm_debug}. recent logs: {debug}"
        )
    item = last_item
    assert item["event_name"]["S"] == "INSERT", (
        f"sink item {pk} recorded eventName={item['event_name']['S']!r}, expected 'INSERT'"
    )


def _recent_lambda_logs(ctx, function_name: str) -> str:
    if not function_name:
        return "<no function name output>"
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    try:
        streams = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime", descending=True, limit=3
        )["logStreams"]
    except ClientError as e:
        return f"<no log group: {e}>"
    lines: list[str] = []
    for s in streams:
        try:
            events = logs.get_log_events(
                logGroupName=group, logStreamName=s["logStreamName"], limit=20, startFromHead=False
            )["events"]
        except ClientError:
            continue
        lines.extend(e["message"].strip() for e in events)
    return " | ".join(lines[-30:]) if lines else "<no log events>"


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
Description: sim2real cfn-ddb-stream-esm-lambda-deployment
Resources:
  SourceTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES

  SinkTable:
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
        - arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole
      Policies:
        - PolicyName: sink-write
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: dynamodb:PutItem
                Resource: !GetAtt SinkTable.Arn

  StreamFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt FunctionRole.Arn
      Timeout: 15
      Environment:
        Variables:
          SINK_TABLE: !Ref SinkTable
      Code:
        ZipFile: |
          import boto3, os
          def handler(event, context):
              table = boto3.resource('dynamodb').Table(os.environ['SINK_TABLE'])
              for record in event['Records']:
                  keys = record['dynamodb']['Keys']
                  pk_val = keys['pk']['S']
                  table.put_item(Item={'id': pk_val, 'event_name': record['eventName']})
              return {'processed': len(event['Records'])}

  StreamEventSourceMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      EventSourceArn: !GetAtt SourceTable.StreamArn
      FunctionName: !Ref StreamFunction
      StartingPosition: TRIM_HORIZON
      BatchSize: 5

Outputs:
  SourceTableName:
    Value: !Ref SourceTable
  SinkTableName:
    Value: !Ref SinkTable
  EsmId:
    Value: !Ref StreamEventSourceMapping
  FunctionName:
    Value: !Ref StreamFunction
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
