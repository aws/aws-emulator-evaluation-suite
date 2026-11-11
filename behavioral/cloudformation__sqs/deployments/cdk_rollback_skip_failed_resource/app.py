#!/usr/bin/env python3
"""Asset-free CDK app whose variant 2 updates a queue, adds a parameter and then fails on a collision.

Context: stack_name, account, region, queue_name, added_name, variant ("1" or "2"). The colliding
parameter waits on the queue, so the queue update has completed before the update fails.
"""
import aws_cdk as cdk
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm

app = cdk.App()
ctx = app.node.get_context
v2 = ctx("variant") == "2"
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
queue = sqs.CfnQueue(stack, "Queue", queue_name=ctx("queue_name"),
                     visibility_timeout=60 if v2 else 30)
if v2:
    added = ssm.CfnParameter(stack, "Added", name=ctx("added_name"), type="String", value="added")
    bad = ssm.CfnParameter(stack, "Bad", name=added.ref, type="String", value="bad")
    bad.node.add_dependency(queue)
app.synth()
