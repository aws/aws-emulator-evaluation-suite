#!/usr/bin/env python3
"""CDK app: one Lambda Function, its current Version, and an Alias pointing at that version.

Context (env):
  account, region  -- the deploy target
  qualifier         -- bootstrap qualifier (DefaultStackSynthesizer)
  stack_name        -- the stack id
  marker            -- echoed back by the handler, so the deployed code is provably this run's
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import json
import os


def handler(event, context):
    return {"marker": os.environ["MARKER"], "echo": event}
"""


class VersionAliasStack(cdk.Stack):
    def __init__(self, scope, sid, *, marker: str, **kwargs):
        super().__init__(scope, sid, **kwargs)
        fn = _lambda.Function(
            self, "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER),
            timeout=cdk.Duration.seconds(30),
            environment={"MARKER": marker},
        )
        version = fn.current_version
        alias = _lambda.Alias(self, "LiveAlias", alias_name="live", version=version)
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)
        cdk.CfnOutput(self, "AliasName", value=alias.alias_name)
        cdk.CfnOutput(self, "VersionNumber", value=version.version)


app = cdk.App()
env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])
synthesizer = cdk.DefaultStackSynthesizer(qualifier=os.environ["QUALIFIER"])
VersionAliasStack(
    app, os.environ["STACK_NAME"], env=env, synthesizer=synthesizer,
    marker=os.environ["MARKER"],
)
app.synth()
