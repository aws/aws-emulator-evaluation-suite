#!/usr/bin/env python3
"""Asset-BEARING CDK app: one Lambda Function whose code comes from `handler/` on disk, deployed
under a context-selected bootstrap qualifier.

The Lambda code is a real, on-disk asset (never inline), so a successful deploy under
`DefaultStackSynthesizer(qualifier=...)` can only have happened by CDK publishing that asset
through the qualifier's FilePublishingRole into the qualifier's staging bucket.

Context:
  stack_name -- the stack id
  qualifier  -- bootstrap qualifier
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class FnBootstrapAssetStack(cdk.Stack):
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
if not qualifier:
    raise ValueError("this app requires a `qualifier` context value")

FnBootstrapAssetStack(
    app,
    app.node.try_get_context("stack_name") or "CdkFnBootstrapAssetStack",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
