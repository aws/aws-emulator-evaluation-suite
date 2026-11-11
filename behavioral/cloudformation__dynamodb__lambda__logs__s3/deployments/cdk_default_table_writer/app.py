#!/usr/bin/env python3
"""CDK app with default version reporting: a function granted read-write on a table.

Context: stack_name, account, region, qualifier, function_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import os

import boto3
from botocore.exceptions import ClientError

TABLE = os.environ["TABLE"]


def handler(event, context):
    item = {"pk": {"S": event["pk"]}, "marker": {"S": event["marker"]}}
    try:
        boto3.client("dynamodb").put_item(TableName=TABLE, Item=item)
    except ClientError as exc:
        return {"error": exc.response["Error"]["Code"]}
    return {"written": event["pk"]}
"""

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
table = ddb.Table(
    stack,
    "Table",
    partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
    billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
    removal_policy=cdk.RemovalPolicy.DESTROY,
)
fn = _lambda.Function(
    stack,
    "Writer",
    function_name=ctx("function_name"),
    runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler",
    code=_lambda.Code.from_inline(HANDLER),
    timeout=cdk.Duration.seconds(30),
    environment={"TABLE": table.table_name},
)
table.grant_read_write_data(fn)
cdk.CfnOutput(stack, "TableName", value=table.table_name)
cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)
app.synth()
