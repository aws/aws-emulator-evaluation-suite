#!/usr/bin/env python3
"""Asset-free CDK app: one wait-condition handle per variant step and an output naming the variant.

Context: stack_name, account, region, variant ("1", "2" or "3").
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
for n in range(1, int(ctx("variant")) + 1):
    cfn.CfnWaitConditionHandle(stack, f"Handle{n}")
cdk.CfnOutput(stack, "Variant", value=ctx("variant"))
app.synth()
