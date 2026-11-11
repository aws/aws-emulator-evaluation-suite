#!/usr/bin/env python3
"""Asset-free CDK app: one wait-condition handle and an output joining AWS::NotificationARNs.

Context: stack_name, account, region.
"""
import aws_cdk as cdk
from aws_cdk import aws_cloudformation as cfn

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
cfn.CfnWaitConditionHandle(stack, "Handle")
cdk.CfnOutput(stack, "NotificationArns", value=cdk.Fn.join(",", cdk.Aws.NOTIFICATION_ARNS))
app.synth()
