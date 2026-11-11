#!/usr/bin/env python3
"""Asset-free CDK app whose SYNTHESIZER is context-selected — the whole subject of its check.

The app has no user assets in either mode. What changes is only which synthesizer builds the cloud
assembly:

  synth=legacy  -- `LegacyStackSynthesizer`. `stackTemplateAssetObjectUrl` is unset, so `cdk deploy`
                   sends `TemplateBody` inline. No bootstrap stack, no staging bucket, no
                   `/cdk-bootstrap/<qualifier>/version` SSM parameter is ever read.
  synth=default -- `DefaultStackSynthesizer(qualifier=<context>)`. The stack TEMPLATE itself becomes
                   a content-addressed file asset, `cdk deploy` switches to `TemplateURL`, and the
                   CLI must resolve `/cdk-bootstrap/<qualifier>/version` before it can publish
                   anything. Against an unbootstrapped qualifier that resolution is what fails.

That contrast is the point: "my app has no assets" does NOT mean "my app needs no bootstrap".

Context:
  stack_name -- the stack id
  synth      -- "legacy" | "default"
  qualifier  -- bootstrap qualifier, only read on the "default" arm
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb


class TableBootstrapStack(cdk.Stack):
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
mode = app.node.try_get_context("synth")
if mode == "default":
    qualifier = app.node.try_get_context("qualifier")
    if not qualifier:
        raise ValueError("synth=default requires a `qualifier` context value")
    synthesizer = cdk.DefaultStackSynthesizer(qualifier=qualifier)
elif mode == "legacy":
    synthesizer = cdk.LegacyStackSynthesizer()
else:
    raise ValueError(f"context `synth` must be 'legacy' or 'default', got {mode!r}")

TableBootstrapStack(
    app,
    app.node.try_get_context("stack_name") or "CdkTableBootstrapStack",
    synthesizer=synthesizer,
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
