#!/usr/bin/env python3
"""Asset-free CDK app: a parameter that succeeds, and a second one that collides with it when broken.

Context: stack_name, account, region, param_name, broken ("1" collides at runtime, "0" does not).
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
keep = ssm.CfnParameter(stack, "Keep", name=ctx("param_name"), type="String", value="keep")
bad_name = keep.ref if ctx("broken") == "1" else ctx("param_name") + "-fixed"
bad = ssm.CfnParameter(stack, "Bad", name=bad_name, type="String", value="bad")
bad.node.add_dependency(keep)
app.synth()
