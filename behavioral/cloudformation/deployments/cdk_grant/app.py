#!/usr/bin/env python3
"""Asset-free CDK app: one Table and two Functions that differ ONLY in which grant they were given.

  ReadOnly  -- `table.grant_read_data(fn)`
  ReadWrite -- `table.grant_read_write_data(fn)`

Both handlers run the SAME two calls against the SAME table with their OWN role credentials —
`GetItem` then `PutItem` — and report, per call, either the value they read or the AWS error code
they got. Nothing about the grant is inferred from a policy document: the answer is produced by two
real signed requests made from inside the deployed function.

The ReadWrite twin exists so the ReadOnly function's `PutItem` failure cannot be explained by
DynamoDB being unreachable from Lambda, by the table not existing, or by a broken handler. It is the
in-file positive control on identical wiring, in the same instant.

Context:
  stack_name -- the stack id
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import os

import boto3
from botocore.exceptions import ClientError

ddb = boto3.client("dynamodb")
TABLE = os.environ["TABLE"]


def _outcome(fn):
    try:
        return {"ok": True, "value": fn()}
    except ClientError as exc:
        err = exc.response["Error"]
        return {"ok": False, "code": err.get("Code"), "message": err.get("Message", "")[:400]}


def handler(event, context):
    read_key = {"pk": {"S": event["read_key"]}}
    write_key = event["write_key"]
    marker = event["marker"]

    def do_read():
        item = ddb.get_item(TableName=TABLE, Key=read_key, ConsistentRead=True).get("Item") or {}
        return item.get("marker", {}).get("S")

    def do_write():
        ddb.put_item(TableName=TABLE, Item={"pk": {"S": write_key}, "marker": {"S": marker}})
        return write_key

    return {"read": _outcome(do_read), "write": _outcome(do_write),
            "role_arn": os.environ["ROLE_HINT"]}
"""


class GrantStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        table = ddb.Table(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        functions = {}
        for label in ("ReadOnly", "ReadWrite"):
            fn = _lambda.Function(
                self,
                label,
                runtime=_lambda.Runtime.PYTHON_3_12,
                handler="index.handler",
                code=_lambda.Code.from_inline(HANDLER),
                timeout=cdk.Duration.seconds(30),
                environment={"TABLE": table.table_name},
            )
            functions[label] = fn

        table.grant_read_data(functions["ReadOnly"])
        table.grant_read_write_data(functions["ReadWrite"])

        for label, fn in functions.items():
            assert fn.role is not None, "the Function L2 always mints an execution role"
            fn.add_environment("ROLE_HINT", fn.role.role_arn)
            cdk.CfnOutput(self, f"{label}FunctionName", value=fn.function_name)
            cdk.CfnOutput(self, f"{label}RoleName", value=fn.role.role_name)

        cdk.CfnOutput(self, "TableName", value=table.table_name)
        cdk.CfnOutput(self, "TableArn", value=table.table_arn)


app = cdk.App()
GrantStack(
    app,
    app.node.try_get_context("stack_name") or "CdkGrantStack",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
