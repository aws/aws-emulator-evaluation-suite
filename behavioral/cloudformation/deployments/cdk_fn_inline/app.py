#!/usr/bin/env python3
"""Asset-free CDK app: one Lambda Function with inline code.

`LegacyStackSynthesizer` on purpose: it leaves `stackTemplateAssetObjectUrl` unset, so `cdk deploy`
sends `TemplateBody` inline and needs no bootstrap staging bucket. See ../README.md.

Context:
  stack_name -- the stack id (so a run is unique per check invocation)
  marker     -- the string the handler echoes back, so the deployed code is provably THIS code
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import os


def handler(event, context):
    return {"marker": os.environ["MARKER"], "n": len(event.get("items", []))}
"""


class FnInlineStack(cdk.Stack):
    def __init__(self, scope, construct_id, marker, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER),
            timeout=cdk.Duration.seconds(30),
            environment={"MARKER": marker},
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
FnInlineStack(
    app,
    app.node.try_get_context("stack_name") or "CdkFnInlineStack",
    marker=app.node.try_get_context("marker") or "unset-marker",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
