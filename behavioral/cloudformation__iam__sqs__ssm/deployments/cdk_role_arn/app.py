#!/usr/bin/env python3
"""Asset-free CDK app: one parameter, plus a queue when with_queue is "1".

Context: stack_name, account, region, param_name, queue_name, with_queue.
"""
import aws_cdk as cdk
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
ssm.CfnParameter(stack, "Param", name=ctx("param_name"), type="String", value="made-by-role")
if ctx("with_queue") == "1":
    sqs.CfnQueue(stack, "Queue", queue_name=ctx("queue_name"))
app.synth()
