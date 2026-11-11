#!/usr/bin/env python3
"""CDK app with default version reporting: a parent stack reading a queue from a nested stack.

The parent outputs the nested queue's URL and stores it in an SSM parameter.

Context: stack_name, account, region, qualifier, queue_name, param_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm


class QueueNest(cdk.NestedStack):
    def __init__(self, scope, construct_id, queue_name, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.queue = sqs.Queue(self, "Queue", queue_name=queue_name)


app = cdk.App()
ctx = app.node.get_context
parent = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
nest = QueueNest(parent, "Nest", queue_name=ctx("queue_name"))
ssm.StringParameter(
    parent, "QueueUrlParam", parameter_name=ctx("param_name"), string_value=nest.queue.queue_url
)
cdk.CfnOutput(parent, "QueueUrl", value=nest.queue.queue_url)
app.synth()
