#!/usr/bin/env python3
"""Asset-free CDK app: one SQS queue, named so its ARN is known before deploy.

Context:
  stack_name -- the stack id
  qualifier  -- bootstrap qualifier (DefaultStackSynthesizer)
  queue_name -- the explicit QueueName, so the resource ARN is deterministic
"""
import aws_cdk as cdk
from aws_cdk import aws_sqs as sqs


class BoundaryQueueStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        queue_name = self.node.try_get_context("queue_name")
        queue = sqs.Queue(self, "Queue", queue_name=queue_name)
        cdk.CfnOutput(self, "QueueUrl", value=queue.queue_url)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
BoundaryQueueStack(
    app,
    app.node.try_get_context("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
