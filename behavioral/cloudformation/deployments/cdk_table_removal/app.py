#!/usr/bin/env python3
"""Asset-free CDK app: two Tables that differ ONLY in their removal policy.

  Retained -- default props. NO `removal_policy` argument is passed, which is the point: the
              DynamoDB L2's default is `RemovalPolicy.RETAIN`, so the synthesised resource carries
              `DeletionPolicy: Retain` / `UpdateReplacePolicy: Retain` and survives `cdk destroy`.
  Destroyed -- the identical table with `removal_policy=DESTROY`. Same instant, same stack, same
              destroy command, opposite outcome — so a target that simply ignores DeletionPolicy
              fails on one table or the other whichever way it errs.

The check that uses this app deletes the survivor itself: its physical name is CDK-generated
(`<stack>-Retained<hash>-<hash>`).

Context:
  stack_name -- the stack id
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb


class TableRemovalStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        key = ddb.Attribute(name="pk", type=ddb.AttributeType.STRING)
        retained = ddb.Table(
            self,
            "Retained",
            partition_key=key,
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
        )
        destroyed = ddb.Table(
            self,
            "Destroyed",
            partition_key=key,
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.CfnOutput(self, "RetainedTableName", value=retained.table_name)
        cdk.CfnOutput(self, "DestroyedTableName", value=destroyed.table_name)


app = cdk.App()
TableRemovalStack(
    app,
    app.node.try_get_context("stack_name") or "CdkTableRemovalStack",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
