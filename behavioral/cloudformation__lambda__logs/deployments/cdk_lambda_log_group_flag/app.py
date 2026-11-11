#!/usr/bin/env python3
"""Asset-free CDK app: one Lambda function with no explicit logGroup or logRetention.

`cdk.json` carries no context block, so `@aws-cdk/aws-lambda:useCdkManagedLogGroup` is supplied
per-synth with `--context`.

Context:
  stack_name -- the stack id
  marker     -- the string the handler echoes back on invoke
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import json
import os


def handler(event, context):
    return {"marker": os.environ["MARKER"]}
"""


class LambdaLogGroupFlagStack(cdk.Stack):
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
LambdaLogGroupFlagStack(
    app,
    app.node.try_get_context("stack_name") or "CdkLambdaLogGroupFlagStack",
    marker=app.node.try_get_context("marker") or "unset-marker",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
