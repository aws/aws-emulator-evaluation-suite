#!/usr/bin/env python3
"""Asset-free CDK app: one Lambda Function whose inline code and timeout are context-driven.

`Code.from_inline` and `LegacyStackSynthesizer` keep the app off the bootstrap path, so a deploy
needs nothing published to a staging bucket — exactly what lets `cdk deploy --hotswap` update the
function directly, with no asset upload in the way.

Context:
  stack_name -- the stack id
  marker     -- string the handler returns, baked into its inline source
  timeout    -- function timeout in seconds
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class HotswapFnStack(cdk.Stack):
    def __init__(self, scope, construct_id, marker, timeout, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(
                f"def handler(event, context):\n    return {{'marker': '{marker}'}}\n"
            ),
            timeout=cdk.Duration.seconds(timeout),
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
HotswapFnStack(
    app,
    app.node.try_get_context("stack_name") or "CdkHotswapFnStack",
    marker=app.node.try_get_context("marker") or "m0",
    timeout=int(app.node.try_get_context("timeout") or "10"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
