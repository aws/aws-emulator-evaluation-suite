#!/usr/bin/env python3
"""Asset-bearing CDK app: one Lambda Function whose code comes from `handler/` on disk.

Publishing it exercises the staging bucket's object-level encryption.

Context:
  stack_name -- the stack id
  qualifier  -- bootstrap qualifier (DefaultStackSynthesizer)
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class CustomerKeyFnAssetStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset("handler"),
            timeout=cdk.Duration.seconds(30),
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
CustomerKeyFnAssetStack(
    app,
    app.node.try_get_context("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
