#!/usr/bin/env python3
"""CDK app: sibling NestedStacks, a producer topic and a consumer queue subscribed to it.

The consumer reads the producer's topic ARN, which CDK wires through the parent as a producer
output passed to a consumer parameter. The only assets are the nested templates, which the CLI
publishes to the check's own bucket with its own credentials, so no `cdk bootstrap` is needed.

Context: stack_name, account, region, asset_bucket, display_name (the producer-only change).
"""

import aws_cdk as cdk
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from aws_cdk import aws_sqs as sqs


class ProducerStack(cdk.NestedStack):
    def __init__(self, scope, construct_id, display_name):
        super().__init__(scope, construct_id)
        self.topic = sns.Topic(self, "Topic", display_name=display_name)


class ConsumerStack(cdk.NestedStack):
    def __init__(self, scope, construct_id, topic):
        super().__init__(scope, construct_id)
        queue = sqs.Queue(self, "Queue", removal_policy=cdk.RemovalPolicy.DESTROY)
        topic.add_subscription(subs.SqsSubscription(queue, raw_message_delivery=True))


app = cdk.App()
ctx = app.node.get_context
parent = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.CliCredentialsStackSynthesizer(file_assets_bucket_name=ctx("asset_bucket")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
producer = ProducerStack(parent, "Producer", ctx("display_name"))
ConsumerStack(parent, "Consumer", producer.topic)
app.synth()
