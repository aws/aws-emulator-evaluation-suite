#!/usr/bin/env python3
"""Asset-free CDK app: the three L2s under test in one stack — Function, Table, LambdaRestApi.

The Function is the only writer of the Table, and the RestApi is the only public way to reach the
Function, so a single real HTTPS request drives the whole chain and the check can read the effect at
the Table with an operation the request never issued.

`removal_policy=DESTROY` is explicit because the DynamoDB L2's default is RETAIN, which would leak a
table past `cdk destroy` on every run.

Context:
  stack_name -- the stack id
"""
import aws_cdk as cdk
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import json
import os

import boto3

ddb = boto3.client("dynamodb")
TABLE = os.environ["TABLE"]


def _act(body):
    key = {"pk": {"S": body["key"]}}
    if body.get("op") == "get":
        item = ddb.get_item(TableName=TABLE, Key=key, ConsistentRead=True).get("Item") or {}
        return {"marker": item.get("marker", {}).get("S")}
    ddb.put_item(TableName=TABLE, Item={"pk": {"S": body["key"]},
                                        "marker": {"S": body["marker"]}})
    return {"wrote": body["key"]}


def handler(event, context):
    if "requestContext" in event:
        out = _act(json.loads(event.get("body") or "{}"))
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps(out)}
    return _act(event)
"""


class TrioStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        table = ddb.Table(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER),
            timeout=cdk.Duration.seconds(30),
            environment={"TABLE": table.table_name},
        )
        table.grant_read_write_data(fn)
        api = apigw.LambdaRestApi(self, "Api", handler=fn)

        cdk.CfnOutput(self, "TableName", value=table.table_name)
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)
        cdk.CfnOutput(self, "RestApiId", value=api.rest_api_id)
        cdk.CfnOutput(self, "InvokeUrl", value=api.url)


app = cdk.App()
TrioStack(
    app,
    app.node.try_get_context("stack_name") or "CdkTrioStack",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
