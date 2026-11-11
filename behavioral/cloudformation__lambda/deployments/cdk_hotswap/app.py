#!/usr/bin/env python3
"""Asset-free CDK app: one inline-code function whose returned body comes from context.

Context: stack_name, account, region, function_name, body. The role grants nothing, so the
function writes no logs and no log group is created.
"""
import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
role = iam.CfnRole(stack, "Role", assume_role_policy_document={
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
lambda_.CfnFunction(
    stack,
    "Function",
    function_name=ctx("function_name"),
    runtime="python3.13",
    handler="index.handler",
    role=role.attr_arn,
    code=lambda_.CfnFunction.CodeProperty(
        zip_file=f'def handler(event, context):\n    return {{"v": "{ctx("body")}"}}\n'),
)
app.synth()
