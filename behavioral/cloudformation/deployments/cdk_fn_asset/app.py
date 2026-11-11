#!/usr/bin/env python3
"""Asset-BEARING CDK app: one Lambda Function whose code comes from `handler/` on disk.

Used SYNTH-ONLY, to show that a CDK file asset's id is a hash of the asset's CONTENT and of nothing
else — the same source synthesises to the same id after the file's mtime changes, and one changed
byte moves exactly the `Code.S3Key` field. It is never deployed, so its `DefaultStackSynthesizer` (which would require a
bootstrapped environment) costs nothing.

`qualifier` is fixed rather than context-driven: it appears in the staging bucket NAME inside the
synthesised template, and the check compares template bytes, so it must not vary between the two
synths it compares.

Context:
  stack_name -- the stack id
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class FnAssetStack(cdk.Stack):
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
FnAssetStack(
    app,
    app.node.try_get_context("stack_name") or "CdkFnAssetStack",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier="hnb659fds"),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
