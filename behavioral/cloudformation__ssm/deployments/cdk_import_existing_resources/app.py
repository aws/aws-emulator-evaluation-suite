#!/usr/bin/env python3
"""Asset-free CDK app holding one named SSM parameter with DeletionPolicy Retain.

Context: stack_name, account, region, param_name. Retain is what lets the parameter be imported.
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
param = ssm.CfnParameter(stack, "Param", name=ctx("param_name"), type="String",
                         value="from-template")
param.apply_removal_policy(cdk.RemovalPolicy.RETAIN)
app.synth()
