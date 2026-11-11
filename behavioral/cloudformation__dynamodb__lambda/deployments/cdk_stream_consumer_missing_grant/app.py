#!/usr/bin/env python3
"""CDK app with default version reporting: one table stream feeding two consumers that each copy
inserts into their own sink table — one granted write on its sink, the other not.

Context: stack_name, account, region, qualifier.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda
from aws_cdk.aws_lambda_event_sources import DynamoEventSource

HANDLER = """
import json
import os

import boto3
from botocore.exceptions import ClientError

ddb = boto3.client("dynamodb")
SINK = os.environ["SINK"]


def handler(event, context):
    copied = 0
    for record in event["Records"]:
        if record["eventName"] != "INSERT":
            continue
        try:
            ddb.put_item(TableName=SINK, Item=record["dynamodb"]["NewImage"])
            copied += 1
        except ClientError as exc:
            err = exc.response["Error"]
            print(json.dumps({"denied_code": err.get("Code"),
                              "denied_message": err.get("Message", "")}))
    return {"copied": copied}
"""

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
source = ddb.Table(
    stack,
    "Source",
    partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
    billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
    stream=ddb.StreamViewType.NEW_IMAGE,
    removal_policy=cdk.RemovalPolicy.DESTROY,
)
sink_good = ddb.Table(
    stack,
    "SinkGood",
    partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
    billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
    removal_policy=cdk.RemovalPolicy.DESTROY,
)
sink_bad = ddb.Table(
    stack,
    "SinkBad",
    partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
    billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
    removal_policy=cdk.RemovalPolicy.DESTROY,
)

good_fn = _lambda.Function(
    stack,
    "GoodConsumer",
    runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler",
    code=_lambda.Code.from_inline(HANDLER),
    timeout=cdk.Duration.seconds(30),
    environment={"SINK": sink_good.table_name},
)
good_fn.add_event_source(DynamoEventSource(
    source, starting_position=_lambda.StartingPosition.TRIM_HORIZON, batch_size=10,
    retry_attempts=1))
sink_good.grant_write_data(good_fn)

bad_fn = _lambda.Function(
    stack,
    "BadConsumer",
    runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler",
    code=_lambda.Code.from_inline(HANDLER),
    timeout=cdk.Duration.seconds(30),
    environment={"SINK": sink_bad.table_name},
)
bad_fn.add_event_source(DynamoEventSource(
    source, starting_position=_lambda.StartingPosition.TRIM_HORIZON, batch_size=10,
    retry_attempts=1))
# Deliberately NOT granted: bad_fn can read the stream but its PutItem into SinkBad is denied.

assert bad_fn.role is not None, "the Function L2 always mints an execution role"
cdk.CfnOutput(stack, "SourceTableName", value=source.table_name)
cdk.CfnOutput(stack, "SinkGoodTableName", value=sink_good.table_name)
cdk.CfnOutput(stack, "SinkBadTableName", value=sink_bad.table_name)
cdk.CfnOutput(stack, "SinkBadTableArn", value=sink_bad.table_arn)
cdk.CfnOutput(stack, "GoodFunctionName", value=good_fn.function_name)
cdk.CfnOutput(stack, "BadFunctionName", value=bad_fn.function_name)
cdk.CfnOutput(stack, "BadRoleName", value=bad_fn.role.role_name)
app.synth()
