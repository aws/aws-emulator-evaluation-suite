#!/usr/bin/env python3
"""Asset-free CDK app: a wait-condition handle, plus a Retain table to import when with_table is 1.

Context: stack_name, account, region, table_name, with_table, and optional tag_value. The table's
key schema and billing mode match the table the check creates out of band.
"""

import aws_cdk as cdk
from aws_cdk import aws_cloudformation as cfn
from aws_cdk import aws_dynamodb as ddb

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
cfn.CfnWaitConditionHandle(stack, "Handle")
if ctx("with_table") == "1":
    tag_value = app.node.try_get_context("tag_value")
    table = ddb.CfnTable(
        stack,
        "Table",
        table_name=ctx("table_name"),
        key_schema=[ddb.CfnTable.KeySchemaProperty(attribute_name="pk", key_type="HASH")],
        attribute_definitions=[
            ddb.CfnTable.AttributeDefinitionProperty(attribute_name="pk", attribute_type="S")
        ],
        billing_mode="PAY_PER_REQUEST",
        tags=[cdk.CfnTag(key="sim2real-stage", value=tag_value)] if tag_value else None,
    )
    table.apply_removal_policy(cdk.RemovalPolicy.RETAIN)
app.synth()
