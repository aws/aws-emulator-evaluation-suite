#!/usr/bin/env python3
"""Asset-free CDK app whose only job is to synthesize under DefaultStackSynthesizer.

DefaultStackSynthesizer makes the TEMPLATE itself a content-addressed asset even though the
app declares no user assets, so the synthesized template carries a CheckBootstrapVersion `Rule`
against `/cdk-bootstrap/<qualifier>/version`. The check submits this template to CloudFormation
directly; this app only produces it.

Context:
  stack_name -- the stack id
  qualifier  -- bootstrap qualifier DefaultStackSynthesizer builds the Rule and asset paths from
  account    -- target account id
  region     -- target region
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb


class BootstrapVersionRuleStack(cdk.Stack):
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
if not qualifier:
    raise ValueError("this app requires a `qualifier` context value")

BootstrapVersionRuleStack(
    app,
    app.node.try_get_context("stack_name") or "BootstrapVersionRuleStack",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
