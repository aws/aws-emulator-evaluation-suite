#!/usr/bin/env python3
"""CDK app with default version reporting: a table with one ALL-projection GSI.

Context: stack_name, account, region, qualifier.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb

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
table.add_global_secondary_index(
    index_name="ByGk",
    partition_key=ddb.Attribute(name="gk", type=ddb.AttributeType.STRING),
    projection_type=ddb.ProjectionType.ALL,
)
cdk.CfnOutput(stack, "TableName", value=table.table_name)
app.synth()
