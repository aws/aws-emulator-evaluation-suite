#!/usr/bin/env python3
"""CDK app with default version reporting: a queue that redrives to a dead-letter queue.

Context: stack_name, account, region, qualifier.
"""

import aws_cdk as cdk
from aws_cdk import aws_sqs as sqs

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
dead_letters = sqs.Queue(stack, "DeadLetters")
work = sqs.Queue(
    stack,
    "Work",
    dead_letter_queue=sqs.DeadLetterQueue(queue=dead_letters, max_receive_count=1),
)
cdk.CfnOutput(stack, "QueueUrl", value=work.queue_url)
cdk.CfnOutput(stack, "DeadLetterQueueUrl", value=dead_letters.queue_url)
app.synth()
