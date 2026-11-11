#!/usr/bin/env python3
"""CDK app: a NestedStack holding a table, and a parent function whose env var is the table's name.

The parent reads the nested table's name and ARN, which CDK passes out as nested stack outputs.
The only asset is the nested template, which the CLI publishes to the check's own bucket with its
own credentials, so no `cdk bootstrap` is needed. The role carries inline policies only.

Context: stack_name, account, region, asset_bucket, function_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_

HANDLER = """
import os

import boto3


def handler(event, context):
    boto3.client("dynamodb").put_item(
        TableName=os.environ["TABLE_NAME"],
        Item={"pk": {"S": event["pk"]}, "marker": {"S": event["marker"]}},
    )
    return {"written": event["pk"]}
"""


class DataStack(cdk.NestedStack):
    def __init__(self, scope, construct_id):
        super().__init__(scope, construct_id)
        self.table = ddb.Table(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )


app = cdk.App()
ctx = app.node.get_context
parent = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.CliCredentialsStackSynthesizer(file_assets_bucket_name=ctx("asset_bucket")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
data = DataStack(parent, "Data")
role = iam.Role(parent, "WriterRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
writer = lambda_.Function(
    parent,
    "Writer",
    function_name=ctx("function_name"),
    runtime=lambda_.Runtime.PYTHON_3_12,
    handler="index.handler",
    code=lambda_.Code.from_inline(HANDLER),
    role=role,
    timeout=cdk.Duration.seconds(30),
    environment={"TABLE_NAME": data.table.table_name},
)
data.table.grant_write_data(writer)
app.synth()
