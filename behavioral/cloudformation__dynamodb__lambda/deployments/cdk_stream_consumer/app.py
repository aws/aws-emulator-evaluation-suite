#!/usr/bin/env python3
"""CDK app with default version reporting: a table stream feeding a function that copies each
inserted item into a second table.

Context: stack_name, account, region, qualifier.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda
from aws_cdk.aws_lambda_event_sources import DynamoEventSource

HANDLER = """
import boto3

import os

ddb = boto3.client("dynamodb")
SINK = os.environ["SINK"]


def handler(event, context):
    copied = 0
    for record in event["Records"]:
        if record["eventName"] != "INSERT":
            continue
        ddb.put_item(TableName=SINK, Item=record["dynamodb"]["NewImage"])
        copied += 1
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
sink = ddb.Table(
    stack,
    "Sink",
    partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
    billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
    removal_policy=cdk.RemovalPolicy.DESTROY,
)
fn = _lambda.Function(
    stack,
    "Consumer",
    runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler",
    code=_lambda.Code.from_inline(HANDLER),
    timeout=cdk.Duration.seconds(30),
    environment={"SINK": sink.table_name},
)
fn.add_event_source(DynamoEventSource(
    source, starting_position=_lambda.StartingPosition.TRIM_HORIZON, batch_size=10,
    retry_attempts=3))
sink.grant_write_data(fn)
cdk.CfnOutput(stack, "SourceTableName", value=source.table_name)
cdk.CfnOutput(stack, "SinkTableName", value=sink.table_name)
cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)
app.synth()
