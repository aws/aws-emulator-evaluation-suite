#!/usr/bin/env python3
"""Asset-free CDK app for `cdk watch`: one Lambda Function whose inline code body and timeout are
literal values in this file, so a check drives each redeploy by rewriting the file on disk — the
same signal `cdk watch`'s own file watcher reacts to — rather than by passing a new --context.

Literals (rewritten in place by the check, never via --context):
  MARKER          -- string the handler returns
  TIMEOUT_SECONDS -- function timeout in seconds
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda

STACK_NAME = "__STACK_NAME__"
ACCOUNT = "__ACCOUNT__"
REGION = "__REGION__"
MARKER = "__MARKER__"
TIMEOUT_SECONDS = int("__TIMEOUT__") if "__TIMEOUT__".isdigit() else 3


class WatchFnStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(
                f"def handler(event, context):\n    return {{'marker': '{MARKER}'}}\n"
            ),
            timeout=cdk.Duration.seconds(TIMEOUT_SECONDS),
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
WatchFnStack(
    app,
    STACK_NAME,
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ACCOUNT, region=REGION),
)
app.synth()
