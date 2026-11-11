#!/usr/bin/env python3
"""Asset-free CDK app: one Table whose point-in-time-recovery setting is context-driven.

PITR is chosen as the diffable property because it is (a) a real deployed setting with its own
independent reader (`DescribeContinuousBackups`, a different API from `DescribeTable`), (b) mutable
out-of-band with a single call (`UpdateContinuousBackups`), and (c) an in-place update rather than a
replacement, so flipping it never destroys the table's contents and the terminal read stays valid.

Context:
  stack_name -- the stack id
  pitr       -- "true" | "false"
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb


class TableDiffableStack(cdk.Stack):
    def __init__(self, scope, construct_id, pitr, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        table = ddb.Table(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=pitr,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.CfnOutput(self, "TableName", value=table.table_name)


app = cdk.App()
TableDiffableStack(
    app,
    app.node.try_get_context("stack_name") or "CdkTableDiffableStack",
    pitr=app.node.try_get_context("pitr") == "true",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
