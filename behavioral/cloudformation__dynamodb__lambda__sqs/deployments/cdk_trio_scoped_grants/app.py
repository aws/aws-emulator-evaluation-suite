#!/usr/bin/env python3
"""CDK app with default version reporting: a function scoped to write a table and send to a queue.

Context: stack_name, account, region, qualifier, function_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_sqs as sqs

HANDLER = """
import os

import boto3
from botocore.exceptions import ClientError

TABLE = os.environ["TABLE"]
QUEUE_URL = os.environ["QUEUE_URL"]


def handler(event, context):
    action = event["action"]
    if action == "write":
        item = {"pk": {"S": event["pk"]}, "marker": {"S": event["marker"]}}
        try:
            boto3.client("dynamodb").put_item(TableName=TABLE, Item=item)
        except ClientError as exc:
            err = exc.response["Error"]
            return {"error": err["Code"], "message": err["Message"]}
        return {"written": event["pk"]}
    if action == "send":
        try:
            result = boto3.client("sqs").send_message(QueueUrl=QUEUE_URL, MessageBody=event["body"])
        except ClientError as exc:
            err = exc.response["Error"]
            return {"error": err["Code"], "message": err["Message"]}
        return {"sent": result["MessageId"]}
    if action == "receive":
        try:
            boto3.client("sqs").receive_message(QueueUrl=QUEUE_URL, WaitTimeSeconds=0)
        except ClientError as exc:
            err = exc.response["Error"]
            return {"error": err["Code"], "message": err["Message"]}
        return {"error": None}
    raise ValueError(f"unknown action {action!r}")
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
queue = sqs.Queue(
    stack,
    "Queue",
    removal_policy=cdk.RemovalPolicy.DESTROY,
)
fn = _lambda.Function(
    stack,
    "Worker",
    function_name=ctx("function_name"),
    runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler",
    code=_lambda.Code.from_inline(HANDLER),
    timeout=cdk.Duration.seconds(30),
    environment={"TABLE": table.table_name, "QUEUE_URL": queue.queue_url},
)
table.grant_read_write_data(fn)
# Send only: no grantConsumeMessages, so the function's own ReceiveMessage is denied.
queue.grant_send_messages(fn)
cdk.CfnOutput(stack, "TableName", value=table.table_name)
cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)
cdk.CfnOutput(stack, "QueueUrl", value=queue.queue_url)
cdk.CfnOutput(stack, "QueueArn", value=queue.queue_arn)
cdk.CfnOutput(stack, "RoleArn", value=fn.role.role_arn)
app.synth()
