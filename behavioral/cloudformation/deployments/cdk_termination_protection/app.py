#!/usr/bin/env python3
"""Asset-free CDK app: one wait-condition handle in a stack whose termination protection is context.

Context: stack_name, account, region, protected ("1" or "0", also echoed as an output).
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
    termination_protection=ctx("protected") == "1",
)
cfn.CfnWaitConditionHandle(stack, "Handle")
cdk.CfnOutput(stack, "Protected", value=ctx("protected"))
app.synth()
