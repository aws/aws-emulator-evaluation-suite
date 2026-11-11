#!/usr/bin/env python3
"""Asset-free CDK app: a wait-condition handle, plus a Retain queue to import when with_queue is "1".

Context: stack_name, account, region, queue_name, with_queue. The queue's VisibilityTimeout matches
the queue the check creates out of band, so the imported resource agrees with the template.
"""
import aws_cdk as cdk
from aws_cdk import aws_cloudformation as cfn
from aws_cdk import aws_sqs as sqs

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
cfn.CfnWaitConditionHandle(stack, "Handle")
if ctx("with_queue") == "1":
    queue = sqs.CfnQueue(stack, "Queue", queue_name=ctx("queue_name"), visibility_timeout=45)
    queue.apply_removal_policy(cdk.RemovalPolicy.RETAIN)
app.synth()
