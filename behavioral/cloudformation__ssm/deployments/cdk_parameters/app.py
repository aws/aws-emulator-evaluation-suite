#!/usr/bin/env python3
"""Asset-free CDK app: a CloudFormation parameter copied into one SSM parameter per variant step.

Context: stack_name, account, region, param_prefix, variant ("1", "2" or "3"). Variant N holds
the parameters <param_prefix>-1 .. <param_prefix>-N, each with the value of Greeting.
"""
import aws_cdk as cdk
from aws_cdk import aws_ssm as ssm

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
greeting = cdk.CfnParameter(stack, "Greeting", type="String", default="default-value")
for n in range(1, int(ctx("variant")) + 1):
    ssm.CfnParameter(stack, f"Copy{n}", name=f"{ctx('param_prefix')}-{n}", type="String",
                     value=greeting.value_as_string)
app.synth()
