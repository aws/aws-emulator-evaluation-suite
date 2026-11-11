#!/usr/bin/env python3
"""Asset-free CDK app: one pay-per-request DynamoDB table.

Context:
  stack_name -- the stack id
  qualifier  -- bootstrap qualifier (DefaultStackSynthesizer)
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb


class BoundaryTableStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        table = ddb.Table(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.CfnOutput(self, "TableName", value=table.table_name)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
BoundaryTableStack(
    app,
    app.node.try_get_context("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
