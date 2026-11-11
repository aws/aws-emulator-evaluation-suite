#!/usr/bin/env python3
"""Asset-free CDK app whose variant 2 updates a queue and a parameter, then fails on a collision.

Context: stack_name, account, region, queue_name, param_name, added_name, variant ("1" or "2").
Variant 2 adds a parameter and a second one named after it, which collides at runtime only after
the queue and parameter updates have completed.
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
keep = ssm.CfnParameter(stack, "Keep", name=ctx("param_name"), type="String",
                        value="v2" if v2 else "v1")
if v2:
    added = ssm.CfnParameter(stack, "Added", name=ctx("added_name"), type="String", value="added")
    bad = ssm.CfnParameter(stack, "Bad", name=added.ref, type="String", value="bad")
    bad.node.add_dependency(queue, keep)
app.synth()
